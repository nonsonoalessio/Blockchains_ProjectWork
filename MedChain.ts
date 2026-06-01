import assert from "node:assert/strict";
import { describe, it, beforeEach } from "node:test";
import { network } from "hardhat";
import { getAddress, pad, toHex } from "viem";

describe("MedChain System: Governance & Vault", async function () {
  const { viem } = await network.connect();

  let gsc: any;
  let msc: any;
  let publicClient: any;

  let ownerClient: any;
  let validator1Client: any;
  let validator2Client: any;
  let doctorClient: any;
  let patientClient: any;

  let ownerAddress: string;
  let val1Address: string;
  let val2Address: string;
  let doctorAddress: string;
  let patientAddress: string;

  const BLINDED_ID = pad(toHex(1), { size: 32 });
  const ROOT_ACT_ID = pad(toHex(10), { size: 32 });
  const CHILD_ACT_ID = pad(toHex(11), { size: 32 });
  const FUTURE_EXPIRATION = 9999999999n;
  const PERM_READ = 0;
  const PERM_WRITE = 1;

  // beforeEach del describe esterno: deploy fresco dei contratti per ogni test
  beforeEach(async function () {
    publicClient = await viem.getPublicClient();
    const clients = await viem.getWalletClients();

    ownerClient = clients[0];
    validator1Client = clients[1];
    validator2Client = clients[2];
    doctorClient = clients[3];
    patientClient = clients[4];

    ownerAddress = getAddress(ownerClient.account.address);
    val1Address = getAddress(validator1Client.account.address);
    val2Address = getAddress(validator2Client.account.address);
    doctorAddress = getAddress(doctorClient.account.address);
    patientAddress = getAddress(patientClient.account.address);

    const validators = [ownerAddress, val1Address, val2Address];
    const threshold = 2n;
    gsc = await viem.deployContract("MedChainGovernance", [validators, threshold]);
    msc = await viem.deployContract("MedChainVault", [gsc.address]);
  });

  // ─────────────────────────────────────────────────────────────
  // GRUPPO 1: Governance Protocol
  // ─────────────────────────────────────────────────────────────
  describe("Governance Protocol (M-of-N)", function () {
    it("Should successfully whitelist a doctor after reaching the threshold", async function () {
      await gsc.write.submitProposal([doctorAddress, true]);
      await gsc.write.signProposal([0n]);

      let proposal = await gsc.read.proposals([0n]);
      assert.equal(proposal[4], false);
      assert.equal(await gsc.read.whitelistedIdentityAuthorities([doctorAddress]), false);

      await validator1Client.writeContract({
        address: gsc.address, abi: gsc.abi,
        functionName: "signProposal", args: [0n],
      });

      assert.equal(await gsc.read.whitelistedIdentityAuthorities([doctorAddress]), true);
    });
  });

  // ─────────────────────────────────────────────────────────────
  // GRUPPO 2: Document Vault & Access Control
  // beforeEach locale: whitelista medico (proposal 0) e paziente (proposal 1)
  // ─────────────────────────────────────────────────────────────
  describe("Document Vault & Access Control", function () {
    beforeEach(async function () {
      await gsc.write.submitProposal([doctorAddress, true]);
      await gsc.write.signProposal([0n]);
      await validator1Client.writeContract({
        address: gsc.address, abi: gsc.abi,
        functionName: "signProposal", args: [0n],
      });

      await gsc.write.submitProposal([patientAddress, true]);
      await gsc.write.signProposal([1n]);
      await validator1Client.writeContract({
        address: gsc.address, abi: gsc.abi,
        functionName: "signProposal", args: [1n],
      });
    });

    it("Should register a new medical document securely", async function () {
      // 1. ASSEGNIAMO la transazione alla variabile const txHash
      const txHash = await patientClient.writeContract({
        address: msc.address,
        abi: msc.abi,
        functionName: "registerDocument", // usa "registerDocument" se nel tuo .sol si chiama così
        args: [BLINDED_ID, "ipfs://my-cid", "0x1234", "0xabcd"],
      });

      // 2. Usiamo txHash per scaricare la ricevuta
      const receipt = await publicClient.getTransactionReceipt({ hash: txHash });
      console.log("-------------------------------------------------");
      console.log("🔥 GAS USATO PER IL DOCUMENTO: ", receipt.gasUsed);
      console.log("-------------------------------------------------");

      // 3. Verifichiamo che i dati siano salvati correttamente
      const doc = await msc.read.vault([BLINDED_ID]);
      assert.equal(doc[0], "ipfs://my-cid"); 
      assert.equal(doc[5], patientAddress);  
    });

    it("Should revert if an unauthorized (non-whitelisted) user tries to issue a document", async function () {
      await assert.rejects(
        validator2Client.writeContract({
          address: msc.address, abi: msc.abi,
          functionName: "registerDocument",
          args: [BLINDED_ID, "ipfs://malicious", "0x00", "0x00"],
        })
      );
    });

    it("Should mint a Root ACT, sub-delegate it, and enforce cascading revocation", async function () {
      const DOCTOR_ACT_ID = pad(toHex(20), { size: 32 });

      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "registerDocument",
        args: [BLINDED_ID, "ipfs://my-cid", "0x1234", "0xabcd"],
      });

      // --- GAS: MINT ROOT ACT ---
      const txHashMint = await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "mintRootAct",
        args: [ROOT_ACT_ID, BLINDED_ID, FUTURE_EXPIRATION],
      });
      const receiptMint = await publicClient.getTransactionReceipt({ hash: txHashMint });
      console.log("🔥 GAS MINT ROOT ACT: ", receiptMint.gasUsed);

      const rootToken = await msc.read.acts([ROOT_ACT_ID]);
      assert.equal(rootToken[1], patientAddress);

      // --- GAS: DELEGATE ACCESS ---
      const txHashDelegate = await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "delegateAccess",
        args: [ROOT_ACT_ID, DOCTOR_ACT_ID, doctorAddress, PERM_WRITE, FUTURE_EXPIRATION],
      });
      const receiptDelegate = await publicClient.getTransactionReceipt({ hash: txHashDelegate });
      console.log("🔥 GAS DELEGATE ACCESS: ", receiptDelegate.gasUsed);

      // Whitelista val1 (proposal 2) per permettere la sub-delega
      await gsc.write.submitProposal([val1Address, true]);
      await gsc.write.signProposal([2n]);
      await validator2Client.writeContract({
        address: gsc.address, abi: gsc.abi,
        functionName: "signProposal", args: [2n],
      });

      await doctorClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "delegateAccess",
        args: [DOCTOR_ACT_ID, CHILD_ACT_ID, val1Address, PERM_READ, FUTURE_EXPIRATION],
      });

      const requestHash = pad(toHex(777), { size: 32 });

      // --- GAS: AUTHORIZE ACCESS ---
      const txHashAuth = await validator1Client.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "authorizeAccess",
        args: [CHILD_ACT_ID, BLINDED_ID, PERM_READ, requestHash],
      });
      const receiptAuth = await publicClient.getTransactionReceipt({ hash: txHashAuth });
      console.log("🔥 GAS AUTHORIZE ACCESS: ", receiptAuth.gasUsed);

      // --- GAS: REVOKE TOKEN ---
      const txHashRevoke = await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "revokeToken", args: [ROOT_ACT_ID],
      });
      const receiptRevoke = await publicClient.getTransactionReceipt({ hash: txHashRevoke });
      console.log("🔥 GAS REVOKE TOKEN: ", receiptRevoke.gasUsed);

      await assert.rejects(
        validator1Client.writeContract({
          address: msc.address, abi: msc.abi,
          functionName: "authorizeAccess",
          args: [CHILD_ACT_ID, BLINDED_ID, PERM_READ, requestHash],
        })
      );
    });

    it("Edge Case 1: Should grant emergency access (Break-Glass) when threshold is met", async function () {
      // --- GAS: REQUEST EMERGENCY ACCESS ---
      const txHashReq = await gsc.write.requestEmergencyAccess([doctorAddress, BLINDED_ID]);
      const receiptReq = await publicClient.getTransactionReceipt({ hash: txHashReq });
      console.log("🔥 GAS REQUEST EMERGENCY ACCESS: ", receiptReq.gasUsed);

      let request = await gsc.read.emergencyRequests([0n]);
      assert.equal(request[4], false);

      // --- GAS: SIGN EMERGENCY REQUEST (Sotto Soglia) ---
      const txHashSignE1 = await gsc.write.signEmergencyRequest([0n]);
      const receiptSignE1 = await publicClient.getTransactionReceipt({ hash: txHashSignE1 });
      console.log("🔥 GAS SIGN EMERGENCY REQUEST (Below Threshold): ", receiptSignE1.gasUsed);

      // --- GAS: SIGN EMERGENCY REQUEST (Soglia Raggiunta) ---
      const txHashSignE2 = await validator1Client.writeContract({
        address: gsc.address, abi: gsc.abi,
        functionName: "signEmergencyRequest", args: [0n],
      });
      const receiptSignE2 = await publicClient.getTransactionReceipt({ hash: txHashSignE2 });
      console.log("🔥 GAS SIGN EMERGENCY REQUEST (Threshold Reached): ", receiptSignE2.gasUsed);

      request = await gsc.read.emergencyRequests([0n]);
      assert.equal(request[4], true);
    });

    it("Edge Case 2: Should prevent DoS by reverting if delegation depth exceeds the maximum limit", async function () {
      const ACT_L1 = pad(toHex(101), { size: 32 });
      const ACT_L2 = pad(toHex(102), { size: 32 });
      const ACT_L3 = pad(toHex(103), { size: 32 });

      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "registerDocument", args: [BLINDED_ID, "ipfs://my-cid", "0x00", "0x00"],
      });
      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "mintRootAct", args: [ROOT_ACT_ID, BLINDED_ID, FUTURE_EXPIRATION],
      });

      // Whitelista val1 (proposal 2) e val2 (proposal 3)
      await gsc.write.submitProposal([val1Address, true]);
      await gsc.write.signProposal([2n]);
      await validator1Client.writeContract({ address: gsc.address, abi: gsc.abi, functionName: "signProposal", args: [2n] });
      await gsc.write.submitProposal([val2Address, true]);
      await gsc.write.signProposal([3n]);
      await validator1Client.writeContract({ address: gsc.address, abi: gsc.abi, functionName: "signProposal", args: [3n] });

      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "delegateAccess", args: [ROOT_ACT_ID, ACT_L1, doctorAddress, PERM_WRITE, FUTURE_EXPIRATION],
      });
      await doctorClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "delegateAccess", args: [ACT_L1, ACT_L2, val1Address, PERM_READ, FUTURE_EXPIRATION],
      });
      await validator1Client.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "delegateAccess", args: [ACT_L2, ACT_L3, val2Address, PERM_READ, FUTURE_EXPIRATION],
      });

      const ACT_L4 = pad(toHex(104), { size: 32 });
      await assert.rejects(
        validator2Client.writeContract({
          address: msc.address, abi: msc.abi,
          functionName: "delegateAccess", args: [ACT_L3, ACT_L4, ownerAddress, PERM_READ, FUTURE_EXPIRATION],
        })
      );
    });

    it("Edge Case 3: Should revert if a malicious user tries to revoke someone else's token", async function () {
      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "registerDocument", args: [BLINDED_ID, "ipfs://my-cid", "0x12", "0xab"],
      });
      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "mintRootAct", args: [ROOT_ACT_ID, BLINDED_ID, FUTURE_EXPIRATION],
      });

      await assert.rejects(
        validator2Client.writeContract({
          address: msc.address, abi: msc.abi,
          functionName: "revokeToken", args: [ROOT_ACT_ID],
        })
      );
    });

    it("Edge Case 4: Should revert if a delegatee tries to use a READ token to authorize WRITE", async function () {
      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "registerDocument",
        args: [BLINDED_ID, "ipfs://my-cid", "0x12", "0xab"],
      });
      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "mintRootAct",
        args: [ROOT_ACT_ID, BLINDED_ID, FUTURE_EXPIRATION],
      });
      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "delegateAccess",
        args: [ROOT_ACT_ID, CHILD_ACT_ID, doctorAddress, PERM_READ, FUTURE_EXPIRATION],
      });

      await assert.rejects(
        doctorClient.writeContract({
          address: msc.address, abi: msc.abi,
          functionName: "authorizeAccess",
          args: [CHILD_ACT_ID, BLINDED_ID, PERM_WRITE, pad(toHex(888), { size: 32 })],
        })
      );
    });

    it("Edge Case 5: Should revert if an expired token is used to authorize access", async function () {
      const PAST_EXPIRATION = 1n;

      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "registerDocument",
        args: [BLINDED_ID, "ipfs://my-cid", "0x12", "0xab"],
      });
      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "mintRootAct",
        args: [ROOT_ACT_ID, BLINDED_ID, PAST_EXPIRATION],
      });

      await assert.rejects(
        patientClient.writeContract({
          address: msc.address, abi: msc.abi,
          functionName: "authorizeAccess",
          args: [ROOT_ACT_ID, BLINDED_ID, PERM_READ, pad(toHex(999), { size: 32 })],
        })
      );
    });

    it("Edge Case 6: Should revert if a revoked token is re-used as parent for delegation", async function () {
      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "registerDocument",
        args: [BLINDED_ID, "ipfs://my-cid", "0x12", "0xab"],
      });
      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "mintRootAct",
        args: [ROOT_ACT_ID, BLINDED_ID, FUTURE_EXPIRATION],
      });
      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "delegateAccess",
        args: [ROOT_ACT_ID, CHILD_ACT_ID, doctorAddress, PERM_WRITE, FUTURE_EXPIRATION],
      });

      await patientClient.writeContract({
        address: msc.address, abi: msc.abi,
        functionName: "revokeToken", args: [CHILD_ACT_ID],
      });

      // Whitelista val1 (proposal 2)
      await gsc.write.submitProposal([val1Address, true]);
      await gsc.write.signProposal([2n]);
      await validator2Client.writeContract({
        address: gsc.address, abi: gsc.abi,
        functionName: "signProposal", args: [2n],
      });

      const GRANDCHILD_ACT_ID = pad(toHex(55), { size: 32 });
      await assert.rejects(
        doctorClient.writeContract({
          address: msc.address, abi: msc.abi,
          functionName: "delegateAccess",
          args: [CHILD_ACT_ID, GRANDCHILD_ACT_ID, val1Address, PERM_READ, FUTURE_EXPIRATION],
        })
      );
    });

  }); // fine describe "Document Vault & Access Control"

}); // fine describe "MedChain System: Governance & Vault"