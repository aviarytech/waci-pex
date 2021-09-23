import {
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  Bls12381G2Key2020,
  Bls12381G2KeyPair,
} from "@transmute/bbs-bls12381-signature-2020";

import { verifiable } from "@transmute/vc.js";
import vc from "vc-js";
import * as fixtures from "../__fixtures__";
import fs from "fs";

describe("waci-pex digitalbazaar-transmute-digitalbazaar", () => {
  let verifiableCredential: any;
  let derivedCredential: any;
  let verification: any;

  afterAll(async () => {
    fs.writeFile(
      "./src/__tests__/digitalbazaar-transmute-digitalbazaar/output.vax-with-ids.json",
      JSON.stringify(
        {
          verification,
          verifiableCredential,
          derivedCredential,
        },
        null,
        2
      ),
      (err) => {
        if (err) console.error(err);
      }
    );
  });
  it("can create credential", async () => {
    const key = fixtures.keys.bls as Bls12381G2Key2020;
    verifiableCredential = await vc.issue({
      credential: {
        ...fixtures.credentials.vaxWithIds,
        issuer: { id: fixtures.keys.bls.controller }, // make sure issuer is set correctly
      },
      documentLoader: fixtures.documentLoader,
      suite: new BbsBlsSignature2020({
        key: await Bls12381G2KeyPair.from(key),
        date: fixtures.credentials.vaxWithIds.issuanceDate,
      }) as any,
    });

    expect(verifiableCredential.proof.type).toBe("BbsBlsSignature2020");
  });

  it("can derive credential", async () => {
    const result = await verifiable.credential.derive({
      credential: verifiableCredential,
      frame: fixtures.frames.vax,
      documentLoader: fixtures.documentLoader,
      suite: new BbsBlsSignatureProof2020(),
    });
    expect(result.items.length).toBe(1);
    expect(result.items[0].proof.type).toBe("BbsBlsSignatureProof2020");
    derivedCredential = result.items[0];
  });

  it("can verify derived credential", async () => {
    verification = await vc.verifyCredential(derivedCredential, {
      documentLoader: fixtures.documentLoader,
      suite: new BbsBlsSignatureProof2020(),
    });
    expect(verification.verified).toBeTruthy();
  });
});
