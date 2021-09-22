import { Bls12381G2KeyPair } from "@mattrglobal/bls12381-key-pair";
import {
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  deriveProof,
} from "@mattrglobal/jsonld-signatures-bbs";

import vc from "vc-js";
import { Suite } from "@transmute/vc.js/dist/types/Suite";
import * as fixtures from "../__fixtures__";
import fs from "fs";

describe("waci-pex digitalbazaar-mattr-digitalbazaar", () => {
  let verifiableCredential: any;
  let derivedCredential: any;
  let verification: any;

  afterAll(async () => {
    fs.writeFile(
      "./src/__tests__/digitalbazaar-mattr-digitalbazaar/output.simple.json",
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
    const key = fixtures.keys.bls;
    const result = await vc.issue({
      credential: {
        ...fixtures.credentials.simple,
        issuer: { id: fixtures.keys.bls.controller }, // make sure issuer is set correctly
      },
      documentLoader: fixtures.documentLoader,
      suite: new BbsBlsSignature2020({
        key: await Bls12381G2KeyPair.from(key),
        date: fixtures.credentials.simple.issuanceDate,
      }) as any,
    });
    expect(result.proof.type).toBe("BbsBlsSignature2020");
    verifiableCredential = result;
  });

  it("can derive credential", async () => {
    const result = await deriveProof(
      verifiableCredential,
      fixtures.frames.simple,
      {
        documentLoader: fixtures.documentLoader,
        suite: new BbsBlsSignatureProof2020() as Suite,
      }
    );
    expect(result.proof.type).toBe("BbsBlsSignatureProof2020");
    derivedCredential = result;
  });

  it("can verify derived credential", async () => {
    verification = await vc.verifyCredential({
      credential: derivedCredential,
      documentLoader: fixtures.documentLoader,
      suite: new BbsBlsSignatureProof2020() as Suite,
    });
    expect(verification.verified).toBeTruthy();
  });
});
