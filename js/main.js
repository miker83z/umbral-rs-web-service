// taken from https://github.com/miker83z/k-DaO/blob/main/index.js

const { AuthService } = require("./lib/auth");
const { BrokerService } = require("./lib/broker");
// const { Web3Wrapper, artifact } = require('./lib/web3Wrapper');
const { publicKeyCreate } = require("secp256k1");
const express = require("express");
const app = express();
const port = 3000;
const path = require("path"); // Add this to the top of your code

app.use(express.static("public"));

const MNEMONIC = process.env.MNEMONIC;

function getRandomInt(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min; // The maximum is inclusive and the minimum is inclusive
}

const sid = getRandomInt(1, 100000); // Generates a random number between 1 and 100 (inclusive)
console.log("current session id:" + sid);

const webapp = async () => {
  const host = "http://127.0.0.1";
  const authPort = 8080;
  const auth = new AuthService(host, authPort);

  const plaintext = "Hello World!";

  // const alice = (await auth.requestKeypair()).data;
  // const signer = (await auth.requestSigner()).data;
  // const bob = (await auth.requestKeypair()).data;

  app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
  });

  app.get("/generateKeypairAlice", async (req, res) => {
    try {
      const alice = (await auth.requestKeypair()).data;
      res.json(alice); // send the result as JSON
    } catch (error) {
      res.status(500).json({ error: "Error generating keypair" });
    }
  });

  app.get("/generateKeypairSigner", async (req, res) => {
    try {
      const alice = (await auth.requestSigner()).data;
      res.json(alice); // send the result as JSON
    } catch (error) {
      res.status(500).json({ error: "Error generating keypair" });
    }
  });

  app.get("/generateKeypairBob", async (req, res) => {
    try {
      const alice = (await auth.requestKeypair()).data;
      res.json(alice); // send the result as JSON
    } catch (error) {
      res.status(500).json({ error: "Error generating keypair" });
    }
  });

  app.listen(port, () => {
    console.log(`App listening on port ${port}`);
  });
};

const test = async () => {
  const host = "http://127.0.0.1";
  const port = 8080;
  const auth = new AuthService(host, port);

  const plaintext = "Hello World!";

  const alice = (await auth.requestKeypair()).data;
  const signer = (await auth.requestSigner()).data;
  const bob = (await auth.requestKeypair()).data;

  const { ciphertext, capsule } = (
    await auth.encrypt({
      plaintext,
      pk: alice.pk,
    })
  ).data;

  const { kfrags } = (
    await auth.generateKfrags({
      sender: alice,
      signer,
      receiver: bob.pk,
      threshold: 2,
      nodes_number: 3,
    })
  ).data;

  const { cfrag: cfrag1 } = (
    await auth.reencrypt({
      sender: alice.pk,
      signer: signer.pk,
      receiver: bob.pk,
      capsule,
      kfrag: kfrags[0],
    })
  ).data;
  const cfrags = [cfrag1];
  // console.log(cfrags)

  const { cfrag: cfrag2 } = (
    await auth.reencrypt({
      sender: alice.pk,
      signer: signer.pk,
      receiver: bob.pk,
      capsule,
      kfrag: kfrags[1],
    })
  ).data;
  cfrags.push(cfrag2);

  const { plaintext: dPlaintext } = (
    await auth.decrypt({
      sender: alice.pk,
      signer: signer.pk,
      receiver: bob,
      capsule,
      ciphertext,
      cfrags,
    })
  ).data;

  console.log(dPlaintext);

  const { resp: res0 } = await auth.keyrefresh({
    sid: sid,
    parties: 5,
    threshold: 3,
    dh_point: [
      3, 248, 92, 16, 145, 125, 119, 97, 185, 247, 94, 147, 17, 90, 84, 1, 142,
      9, 237, 202, 165, 133, 107, 110, 221, 41, 181, 30, 142, 238, 111, 228,
      107,
    ],
    precursor: [
      2, 73, 132, 47, 131, 129, 0, 31, 112, 153, 107, 119, 88, 77, 130, 198,
      122, 160, 149, 24, 220, 229, 127, 18, 206, 210, 175, 208, 117, 133, 182,
      202, 186,
    ],
    delegatee_key: [
      2, 177, 68, 125, 44, 113, 169, 50, 229, 3, 234, 78, 206, 105, 227, 167,
      244, 76, 218, 133, 255, 29, 140, 140, 160, 125, 132, 165, 145, 88, 61, 6,
      139,
    ],
    id: "CFB8AA869E8941B58E680B88D9673EFBA345A38D37B00D6ADE35B00F67A08F80",
    sk: [
      44, 170, 187, 26, 236, 53, 108, 172, 179, 38, 244, 251, 72, 246, 178, 208,
      7, 129, 111, 206, 4, 55, 22, 249, 136, 189, 115, 168, 246, 217, 245, 116,
    ],
  });

  const { resp: res1 } = (
    await auth.keyrefresh({
      sid: sid,
      parties: 5,
      threshold: 3,
      dh_point: [
        3, 248, 92, 16, 145, 125, 119, 97, 185, 247, 94, 147, 17, 90, 84, 1,
        142, 9, 237, 202, 165, 133, 107, 110, 221, 41, 181, 30, 142, 238, 111,
        228, 107,
      ],
      precursor: [
        2, 73, 132, 47, 131, 129, 0, 31, 112, 153, 107, 119, 88, 77, 130, 198,
        122, 160, 149, 24, 220, 229, 127, 18, 206, 210, 175, 208, 117, 133, 182,
        202, 186,
      ],
      delegatee_key: [
        2, 177, 68, 125, 44, 113, 169, 50, 229, 3, 234, 78, 206, 105, 227, 167,
        244, 76, 218, 133, 255, 29, 140, 140, 160, 125, 132, 165, 145, 88, 61,
        6, 139,
      ],
      id: "5959A6AE444C989EBD096EFDC46C8BFEBEA0D031D472008FFBB6F2347FC82CC0",
      sk: [
        143, 95, 152, 35, 162, 113, 72, 18, 107, 104, 187, 44, 134, 2, 107, 37,
        248, 161, 234, 237, 41, 72, 248, 177, 120, 147, 58, 77, 130, 244, 100,
        142,
      ],
    })
  ).data;

  const { resp: res2 } = (
    await auth.keyrefresh({
      sid: sid,
      parties: 5,
      threshold: 3,
      dh_point: [
        3, 248, 92, 16, 145, 125, 119, 97, 185, 247, 94, 147, 17, 90, 84, 1,
        142, 9, 237, 202, 165, 133, 107, 110, 221, 41, 181, 30, 142, 238, 111,
        228, 107,
      ],
      precursor: [
        2, 73, 132, 47, 131, 129, 0, 31, 112, 153, 107, 119, 88, 77, 130, 198,
        122, 160, 149, 24, 220, 229, 127, 18, 206, 210, 175, 208, 117, 133, 182,
        202, 186,
      ],
      delegatee_key: [
        2, 177, 68, 125, 44, 113, 169, 50, 229, 3, 234, 78, 206, 105, 227, 167,
        244, 76, 218, 133, 255, 29, 140, 140, 160, 125, 132, 165, 145, 88, 61,
        6, 139,
      ],
      id: "93BEFAC409E4A863A0F26ADC6508C75A7D5FD7EBB479400206E8BBF5B0539EB7",
      sk: [
        37, 182, 132, 105, 81, 179, 163, 95, 248, 10, 29, 72, 235, 128, 54, 200,
        95, 99, 60, 44, 151, 201, 75, 31, 130, 181, 23, 33, 171, 158, 153, 116,
      ],
    })
  ).data;

  const { resp: res3 } = (
    await auth.keyrefresh({
      sid: sid,
      parties: 5,
      threshold: 3,
      dh_point: [
        3, 248, 92, 16, 145, 125, 119, 97, 185, 247, 94, 147, 17, 90, 84, 1,
        142, 9, 237, 202, 165, 133, 107, 110, 221, 41, 181, 30, 142, 238, 111,
        228, 107,
      ],
      precursor: [
        2, 73, 132, 47, 131, 129, 0, 31, 112, 153, 107, 119, 88, 77, 130, 198,
        122, 160, 149, 24, 220, 229, 127, 18, 206, 210, 175, 208, 117, 133, 182,
        202, 186,
      ],
      delegatee_key: [
        2, 177, 68, 125, 44, 113, 169, 50, 229, 3, 234, 78, 206, 105, 227, 167,
        244, 76, 218, 133, 255, 29, 140, 140, 160, 125, 132, 165, 145, 88, 61,
        6, 139,
      ],
      id: "615FEB0C83CF9FA3B84AEFA1A29B9E380AA8BD64BC8F4A581E0B91B247CCF5E3",
      sk: [
        78, 191, 113, 132, 124, 232, 199, 128, 147, 26, 234, 133, 69, 124, 36,
        147, 124, 15, 202, 38, 202, 103, 215, 32, 136, 162, 49, 241, 240, 111,
        68, 204,
      ],
    })
  ).data;

  const { resp: res4 } = (
    await auth.keyrefresh({
      sid: sid,
      parties: 5,
      threshold: 3,
      dh_point: [
        3, 248, 92, 16, 145, 125, 119, 97, 185, 247, 94, 147, 17, 90, 84, 1,
        142, 9, 237, 202, 165, 133, 107, 110, 221, 41, 181, 30, 142, 238, 111,
        228, 107,
      ],
      precursor: [
        2, 73, 132, 47, 131, 129, 0, 31, 112, 153, 107, 119, 88, 77, 130, 198,
        122, 160, 149, 24, 220, 229, 127, 18, 206, 210, 175, 208, 117, 133, 182,
        202, 186,
      ],
      delegatee_key: [
        2, 177, 68, 125, 44, 113, 169, 50, 229, 3, 234, 78, 206, 105, 227, 167,
        244, 76, 218, 133, 255, 29, 140, 140, 160, 125, 132, 165, 145, 88, 61,
        6, 139,
      ],
      id: "585B01A63A80C839EE73CA313E79C25710D78C9A11893C9BF4856EED02622637",
      sk: [
        116, 141, 216, 95, 237, 86, 68, 78, 133, 106, 213, 208, 119, 92, 122,
        33, 183, 143, 147, 147, 197, 71, 230, 208, 109, 229, 62, 70, 200, 4, 12,
        39,
      ],
    })
  ).data;

  for (let i = 0; i <= 4; i++) {
    console.log("response " + i + ":", eval("res" + i));
  }
};

const testSignature = async () => {
  const host = "http://127.0.0.1";
  const port = 8022;
  const auth = new AuthService(host, port);

  const data = "Hello World 2";
  const signer = (await auth.requestSigner()).data;

  const { signature } = (
    await auth.sign({
      signer,
      data,
    })
  ).data;

  const { verified } = (
    await auth.verify({
      signature,
      data,
      pk: signer.pk,
    })
  ).data;

  console.log("Signature verified: " + verified);
};

const testContracts = async () => {
  const provider = new HDWalletProvider(MNEMONIC, "http://127.0.0.1:8545");
  try {
    const deployer = new Web3Wrapper(provider);
    const accounts = await deployer.web3.eth.getAccounts();
    const owner = accounts[0];
    const alice = accounts[1];
    const bob = accounts[2];

    ///////////////////////////// Setup
    // ERC20 Token
    const token = await deployer.deploy(artifact.kDaOToken, owner, [
      "kDaOToken",
      "kDaO",
      100000,
    ]);

    //Timelock implementation
    const timelockImplementation = await deployer.deploy(
      artifact.SimpleTimelockUpgradeable,
      owner
    );

    //Timelock proxy
    const proxy = await deployer.deploy(artifact.TokenTimelockProxy, owner, [
      token.options.address,
      timelockImplementation.options.address,
    ]);

    //kDaO
    const kDaOImplementation = await deployer.deploy(artifact.kDaO, owner);

    //DataOwnerContract
    const docOwner = await deployer.deployDataOwnerContract(owner);
    const docAlice = await deployer.deployDataOwnerContract(alice);
    const docBob = await deployer.deployDataOwnerContract(bob);

    console.log(docOwner.address, docAlice.address, docBob.address);

    //AggregatorContract
    const agg = await deployer.deploy(artifact.AggregatorContract, owner, [
      token.options.address,
      kDaOImplementation.options.address,
      proxy.options.address,
    ]);
    ///////////////////////////////////////////////////

    ///////////////////// Operations
    const amountToStake = 10;
    let kDaOAddress = "0x0";
    const millisToWait = 9000;
    const debatingPeriodMul = 2;
    const reasons = deployer.web3.utils.utf8ToHex("some reasons");

    //should transfer 100 tokens to alice and bob'
    const res1 = await token.methods.transfer(alice, 100).send({
      from: owner,
    });
    const res2 = await token.methods.transfer(bob, 100).send({
      from: owner,
    });
    //should grant access to alice and bob
    const dataId = deployer.web3.utils.utf8ToHex("dataId1");
    const res3 = await docOwner.grantAccess([alice, bob], dataId);
    const res4 = await docOwner.checkPermissions(alice, dataId);
    //should grant access to alice after a request
    const res5 = await docOwner.requestAccess([alice], dataId, reasons, alice);
    const reqId = res5.events.NewRequest.returnValues.requestId;
    const res6 = await docOwner.grantAccessRequest(reqId);
    // should revoke access to alice
    const res7 = await docOwner.revokeAccess([alice], dataId);

    //aggregator should request access to alice and bob
    const dataIdAlice = deployer.web3.utils.utf8ToHex("dataIdAlice");
    const dataIdBob = deployer.web3.utils.utf8ToHex("dataIdBob");
    const releaseDatePeriod = Math.floor(
      (millisToWait * debatingPeriodMul * debatingPeriodMul) / 1000
    );
    const parameters = [releaseDatePeriod, 1, 1, 1, 1, 1000, 1];
    const res8 = await agg.methods
      .requestAccessToData(
        [dataIdAlice, dataIdBob],
        [docAlice.address, docBob.address],
        [owner],
        reasons,
        parameters
      )
      .send({
        from: owner,
      });

    const reqIdAlice = res8.events.NewAggregation.returnValues.requestIds[0];
    const reqIdBob = res8.events.NewAggregation.returnValues.requestIds[1];
    const aggId = res8.events.NewAggregation.returnValues.aggregationId;

    const res9 = await docAlice.grantAccessRequest(reqIdAlice);
    const res10 = await docBob.grantAccessRequest(reqIdBob);

    const checkKgtM = await agg.methods.checkKgtM(aggId).call();
    console.log(checkKgtM);
  } catch (error) {
    console.log(error);
  } finally {
    provider.engine.stop();
  }
};

const testBroker = async () => {
  const provider = new HDWalletProvider(MNEMONIC, "http://127.0.0.1:8545");
  try {
    const host = "http://127.0.0.1";
    const auth = new AuthService(host, 8024);
    const broker = new BrokerService(host, 3164);
    const deployer = new Web3Wrapper(provider);

    //const accounts = await deployer.web3.eth.getAccounts();
    //console.log(provider.wallets[accounts[0]].getPrivateKeyString().slice(2));
    const accounts = Object.keys(provider.wallets);
    ////////////// Owner
    const aggregator = accounts[0];
    const aggregatorSkUint8 = new Uint8Array(
      provider.wallets[aggregator].privateKey
    );
    const aggregatorPkUint8 = publicKeyCreate(aggregatorSkUint8, true);
    const aggregatorKeypair = {
      pk: Array.from(aggregatorPkUint8),
      sk: Array.from(aggregatorSkUint8),
    };
    const { pk: aggregatorSignerPkUint8, sk: aggregatorSignerSkUint8 } = (
      await auth.requestSigner()
    ).data;
    const aggregatorSignerKeypair = {
      pk: Array.from(aggregatorSignerPkUint8),
      sk: Array.from(aggregatorSignerSkUint8),
    };
    const aggregatorSigner = deployer.web3.eth.accounts.privateKeyToAccount(
      "0x" + Buffer.from(aggregatorSignerSkUint8).toString("hex")
    ).address;
    ////////////// Alice
    const doAlice = accounts[1];
    const doAliceSkUint8 = new Uint8Array(provider.wallets[doAlice].privateKey);
    const doAlicePkUint8 = publicKeyCreate(doAliceSkUint8, true);
    const doAliceKeypair = {
      pk: Array.from(doAlicePkUint8),
      sk: Array.from(doAliceSkUint8),
    };
    const { pk: doAliceSignerPkUint8, sk: doAliceSignerSkUint8 } = (
      await auth.requestSigner()
    ).data;
    const doAliceSignerKeypair = {
      pk: Array.from(doAliceSignerPkUint8),
      sk: Array.from(doAliceSignerSkUint8),
    };
    ////////////// Bob
    const doBob = accounts[2];
    const doBobSkUint8 = new Uint8Array(provider.wallets[doBob].privateKey);
    const doBobPkUint8 = publicKeyCreate(doBobSkUint8, true);
    const doBobKeypair = {
      pk: Array.from(doBobPkUint8),
      sk: Array.from(doBobSkUint8),
    };
    const { pk: doBobSignerPkUint8, sk: doBobSignerSkUint8 } = (
      await auth.requestSigner()
    ).data;
    const doBobSignerKeypair = {
      pk: Array.from(doBobSignerPkUint8),
      sk: Array.from(doBobSignerSkUint8),
    };

    ///////////////////////////// Setup
    // ERC20 Token
    const token = await deployer.deploy(artifact.kDaOToken, aggregator, [
      "kDaOToken",
      "kDaO",
      100000,
    ]);

    //Timelock implementation
    const timelockImplementation = await deployer.deploy(
      artifact.SimpleTimelockUpgradeable,
      aggregator
    );

    //Timelock proxy
    const proxy = await deployer.deploy(
      artifact.TokenTimelockProxy,
      aggregator,
      [token.options.address, timelockImplementation.options.address]
    );

    //kDaO
    const kDaOImplementation = await deployer.deploy(artifact.kDaO, aggregator);

    //DataOwnerContract
    const docOwner = await deployer.deployDataOwnerContract(aggregator);
    const docAlice = await deployer.deployDataOwnerContract(doAlice);
    const docBob = await deployer.deployDataOwnerContract(doBob);

    //AggregatorContract
    const agg = await deployer.deploy(artifact.AggregatorContract, aggregator, [
      token.options.address,
      kDaOImplementation.options.address,
      proxy.options.address,
    ]);
    ///////////////////////////////////////////////////

    ///////////////////// Operations
    const millisToWait = 9000;
    const debatingPeriodMul = 2;
    const reasons = deployer.web3.utils.utf8ToHex("some reasons");

    //aggregator should request access to doAlice and doBob
    const dataIdAlice = deployer.web3.utils.utf8ToHex("dataIdAlice");
    const dataIdBob = deployer.web3.utils.utf8ToHex("dataIdBob");
    const releaseDatePeriod = Math.floor(
      (millisToWait * debatingPeriodMul * debatingPeriodMul) / 1000
    );
    const parameters = [releaseDatePeriod, 1, 1, 1, 1, 1000, 1];
    const res8 = await agg.methods
      .requestAccessToData(
        [dataIdAlice, dataIdBob],
        [docAlice.address, docBob.address],
        [aggregatorSigner],
        reasons,
        parameters
      )
      .send({
        from: aggregator,
      });

    const reqIdAlice = res8.events.NewAggregation.returnValues.requestIds[0];
    const reqIdBob = res8.events.NewAggregation.returnValues.requestIds[1];
    await docAlice.grantAccessRequest(reqIdAlice);
    await docBob.grantAccessRequest(reqIdBob);

    const plaintext = "Hello World!";

    const { ciphertext, capsule } = (
      await auth.encrypt({
        plaintext,
        pk: doAliceKeypair.pk,
      })
    ).data;

    const { kfrags } = (
      await auth.generateKfrags({
        sender: doAliceKeypair,
        signer: doAliceSignerKeypair,
        receiver: aggregatorKeypair.pk,
        threshold: 1,
        nodes_number: 4,
      })
    ).data;

    await broker.storeCapsule({
      sender: doAliceKeypair.pk,
      dataId: "dataIdAlice",
      capsule,
    });

    await broker.storeKFrag({
      sender: doAliceKeypair.pk,
      receiver: aggregatorKeypair.pk,
      kfrag: kfrags[0],
    });

    await broker.generateCFrag({
      sender: doAliceKeypair.pk,
      signer: doAliceSignerKeypair.pk,
      dataId: "dataIdAlice",
      receiver: aggregatorKeypair.pk,
    });

    const dataToSign = "sign this pls";

    const { signature } = (
      await auth.sign({
        signer: aggregatorSignerKeypair,
        data: dataToSign,
      })
    ).data;

    const cfrag1 = (
      await broker.getCFrag({
        address: docAlice.address,
        dataId: "dataIdAlice",
        sender: doAliceKeypair.pk,
        signer: aggregatorSignerKeypair.pk,
        signature,
        receiver: aggregatorKeypair.pk,
      })
    ).data;

    const cfrags = [cfrag1.result];

    const { plaintext: dPlaintext } = (
      await auth.decrypt({
        sender: doAliceKeypair.pk,
        signer: doAliceSignerKeypair.pk,
        receiver: aggregatorKeypair,
        capsule,
        ciphertext,
        cfrags,
      })
    ).data;

    console.log(dPlaintext);
  } catch (error) {
    console.log(error);
  } finally {
    provider.engine.stop();
  }
};

const main = async () => {
  try {
    // await test();
    //await testSignature();
    //await testContracts();
    // await testBroker();
    await webapp();
  } catch (error) {
    console.log(error);
  }
};

main();
