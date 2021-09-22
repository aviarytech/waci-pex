import { Bls12381G2KeyPair } from "@mattrglobal/bls12381-key-pair";
import {
  BbsBlsSignature2020,
  BbsBlsSignatureProof2020,
  deriveProof,
} from "@mattrglobal/jsonld-signatures-bbs";

import { verifiable } from "@transmute/vc.js";
import { Suite } from "@transmute/vc.js/dist/types/Suite";
import * as fixtures from "../__fixtures__";
import fs from "fs";

describe("waci-pex transmute-mattr-transmute", () => {
  let verifiableCredential: any;
  let derivedCredential: any;
  let verification: any;

  afterAll(async () => {
    fs.writeFile(
      "./src/__tests__/transmute-mattr-transmute/ouput.simple.json",
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
    const result = await verifiable.credential.create({
      credential: {
        ...fixtures.credentials.simple,
        issuer: { id: fixtures.keys.bls.controller }, // make sure issuer is set correctly
      },
      format: ["vc"],
      documentLoader: fixtures.documentLoader,
      suite: new BbsBlsSignature2020({
        key: await Bls12381G2KeyPair.from(key),
        date: fixtures.credentials.simple.issuanceDate,
      }) as any,
    });

    expect(result.items.length).toBe(1);
    verifiableCredential = result.items[0];
    expect(result.items[0].proof.type).toBe("BbsBlsSignature2020");
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
    derivedCredential = result;
    expect(result.proof.type).toBe("BbsBlsSignatureProof2020");
  });

  it("can verify derived credential", async () => {
    const result = await verifiable.credential.verify({
      credential: derivedCredential,
      documentLoader: fixtures.documentLoader,
      suite: new BbsBlsSignatureProof2020() as Suite,
    });

    verification = result;
    expect(result.verified).toBeTruthy();
  });
});
