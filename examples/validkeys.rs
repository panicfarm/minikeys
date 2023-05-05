use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash;
use bitcoin::{absolute::LockTime, Sequence};
use hex_lit::hex;
use miniscript::interpreter::KeySigPair;

//These are real blockchain transactions examples of computing sighash for:
// - P2WPKH
// - P2MS 2of3
// - P2SH 2of2 multisig
// - P2WSH 2of2 multisig

//run with: cargo run --example sighash

//TODO add P2TR examples, ideally for both key-path and script-path spending

fn main() {
    test_sighash_p2ms_multisig_2x3();
    test_sighash_p2sh_multisig_2x3();
    test_sighash_p2sh_multisig_2x2();
    test_sighash_p2wsh_multisig_2x2();
    test_sighash_p2tr_multisig_1x2();
    test_sighash_p2tr_multisig_2x2();
}

fn test_sighash_p2sh_multisig_2x2() {
    //Spending transactoin:
    //bitcoin-cli getrawtransaction 214646c4b563cd8c788754ec94468ab71602f5ed07d5e976a2b0e41a413bcc0e  3
    //after decoding ScriptSig from the input:0, its last ASM element is the scriptpubkey:
    //bitcoin-cli decodescript 5221032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de2103e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af565752ae
    //its ASM is 2 of 2 multisig: 2 032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de 03e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af5657 2 OP_CHECKMULTISIG
    let raw_tx = hex!("0100000001d611ad58b2f5bc0db7d15dfde4f497d6482d1b4a1e8c462ef077d4d32b3dae7901000000da0047304402203b17b4f64fa7299e8a85a688bda3cb1394b80262598bbdffd71dab1d7f266098022019cc20dc20eae417374609cb9ca22b28261511150ed69d39664b9d3b1bcb3d1201483045022100cfff9c400abb4ce5f247bd1c582cf54ec841719b0d39550b714c3c793fb4347b02201427a961a7f32aba4eeb1b71b080ea8712705e77323b747c03c8f5dbdda1025a01475221032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de2103e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af565752aeffffffff020ed000000000000016001477800cff52bd58133b895622fd1220d9e2b47a79cd0902000000000017a914da55145ca5c56ba01f1b0b98d896425aa4b0f4468700000000");
    let raw_reftx = hex!("0100000001ade1ff3b7e2da73914f831ef20ab26bb861f60b7659ff7de3af07137d973a17402000000da00473044022039c919ba99640e2256b8b56c22278997bfdc24a78b72e9dd7e232d0a5650c01702204a15618469c4f0978e123d391f833f7bc6dc9e3b7d22f79d492e0c70a6aa704701483045022100983973c309c05ab8a6002e1ea663fb44227b1b8eaaaeb2d63e6c39a595f02a78022020fd7cc11660bf10cef660a0256276a9b378d236b30fe3a9f900448a7d5de0b201475221032d7306898e980c66aefdfb6b377eaf71597c449bf9ce741a3380c5646354f6de2103e8c742e1f283ef810c1cd0c8875e5c2998a05fc5b23c30160d3d33add7af565752aeffffffff02b5ba0000000000001976a914c91852f5780f02a7f8884f05037547594ac3cb8988ac5ce002000000000017a914da55145ca5c56ba01f1b0b98d896425aa4b0f4468700000000");

    println!("\n\n======== sighash_p2sh_multisig_2x2:\n");
    vrfy_pks(&raw_tx, 0, &raw_reftx);
}

fn test_sighash_p2sh_multisig_2x3() {
    //Spending transactoin:
    //bitcoin-cli getrawtransaction 3
    //after decoding ScriptSig from the input:0, its last ASM element is the scriptpubkey:
    //bitcoin-cli decodescript
    //its ASM is 2 of 3 multisig:
    let raw_tx = hex!("010000000a2aafcf32a7d0998e146f02d9948b8530a7c574f24e51ac4e5f8009dc8121228800000000fdfd000047304402205b959fc960be4256a6fe61f75013beb552f7f78352c4b8ddf5cd9747a7757af702207e540d95c8be8b096976685f61ec9d38ccaf68903c34ada54b9878ce21c40d3b014830450221009d2386c125126dcf7a90b85145b57983c4777b6d31526bb01c3dc44ad6b66d3f02205bfdfe89a6114d2d9e5d27f090fad46393251510777880817db65ada47ee3c49014c69522102261f84d51bb64371cb5e9eec3bbc0c0c7320eb7fa9c5076a394a48a9cd74bfd321023e66621cf94ac25d8bb687abef86d01847805d6e9bff8c3999f18f478cde5ab62102d844059fae247b8e1325f56519d1eb7d4b632ec77b9f71f03102167f3c7fa59153aeffffffff902196cd0936b8854a2f6a748c4a15ce397bb213e59599f809ac823b9fd2dec700000000fdfd0000483045022100dc2e50c9f852edf89a9d295995c91bb07857c3b18e98549b68c2b45a76f4b608022076cfff6d39245b7b8602691cbe9466a254b398d3d9f114a63a59febae645449401473044022012f66786119c435832fb715520232f45c7b541d68db0158c2d1e13b27c7b4dcd022051011c7bb2256236ca238a935bace3f073c851111fa9274fa609422d77cb617f014c69522102261f84d51bb64371cb5e9eec3bbc0c0c7320eb7fa9c5076a394a48a9cd74bfd321023e66621cf94ac25d8bb687abef86d01847805d6e9bff8c3999f18f478cde5ab62102d844059fae247b8e1325f56519d1eb7d4b632ec77b9f71f03102167f3c7fa59153aeffffffff2e9dbb1cabff6041ea2951105f877fb14addb45fa42e70eaec2d1ab17e0d37c300000000fdfe0000483045022100c1510121f06ee1cf200ef9dc19cc5fff5f6a2ec087dc618e39c053eb397722a202203672ac3c49a0d9f332efcd03801bc7d68e9d4bc6b84e77591f22d7088108baca01483045022100baf85a48dd5b90b95e94961a54ce6d004d0ab0d6c82e898f4038654d284ffb77022002719f0b1c5bf069a296df8df40fce65ed5922a6469fd2b5774714b742a59893014c69522102261f84d51bb64371cb5e9eec3bbc0c0c7320eb7fa9c5076a394a48a9cd74bfd321023e66621cf94ac25d8bb687abef86d01847805d6e9bff8c3999f18f478cde5ab62102d844059fae247b8e1325f56519d1eb7d4b632ec77b9f71f03102167f3c7fa59153aeffffffff7ae4f4513dc761a41855b7ec5f111e192fd40f0490aa6b01c0cbb9f32585db9c00000000fdfd0000473044022065ac8212e0fda09bc286169af551fa90ab20b54c28acc8bbb3c44e3a0f2af5de022056d41d30a2b845fba3c0e80d1fe4991b36717608b0bd3e5e31f8a7c5f608a1b9014830450221008f9c17289fcc945e9ffed612a779962faaa477e36400288708766b11e3b75c7602207e2b4994fd7ac2a8d06cf676d4819de1880b597f90ca1a97fac5f92a4af2ffd7014c69522102261f84d51bb64371cb5e9eec3bbc0c0c7320eb7fa9c5076a394a48a9cd74bfd321023e66621cf94ac25d8bb687abef86d01847805d6e9bff8c3999f18f478cde5ab62102d844059fae247b8e1325f56519d1eb7d4b632ec77b9f71f03102167f3c7fa59153aeffffffff924c652d9953c90ba157e17009f3d609f3e9c74944b1905098c34f7cebdf307b01000000fc004730440220229015b2578422b9cfc67a7ae63956cba017efd3a85546dc26b482bd2a0ac3fe02206447c1f8e27784a796ded47988d0ddf57f1ec35bd2e3fea85ce1698f057d7e550147304402206de04ad86eac89ee9faeaadf9111a28c6dbb11f0f13e759dcafdece70c30843702204dd198460c0877eb3c006205750f1d221b76c0a92efadd27c848974545da305a014c69522102d828f488cb7999b5e8f86d96ffdfca8df623b9c69110deb17bebbf078fba5c712102ddb0d4d376eddf45d3342dc10ff990a8824a8ee27cbf677d8b8598e95d39dfa021037ec133aafd59281211f544672eeae73d41c7997c93f339dc7656a8d3dd7564e053aeffffffff9e34c86d4547fa8a66a34cf2261da011e4d7b32110273881678c58ad65af6deb00000000fdfe0000483045022100cf6c69951457ec074ade356043089d9ebadb53cc003be857c0de9c884cac4d6102205616d1ab0e0c11d602247d379436b6500a1d07c774ad61dc944a53cdee1809d101483045022100a7e9e63c92108cc3ac014ddd593755feec949bdae2450de001dadfe94038a1b8022033ba6ca06ee46e3808dd027c27f5cb630fc1bd6807487ec7af2c789854daba4f014c69522102d828f488cb7999b5e8f86d96ffdfca8df623b9c69110deb17bebbf078fba5c712102ddb0d4d376eddf45d3342dc10ff990a8824a8ee27cbf677d8b8598e95d39dfa021037ec133aafd59281211f544672eeae73d41c7997c93f339dc7656a8d3dd7564e053aeffffffffafde87dca43f6b06dbe1520a9389ad31e70af9e3324bf9c1bca013b1bb76fdc900000000fdfd00004730440220727a0e2be9949e991ab5ff203001281127a7b5d13a1b3ca9b7276333f9371b3602206a3f07b6879eae1759046a1ce47b4a303587eaf47aada346b19b8924fb99d80e01483045022100e4a947ccf698f670ef45b5963cd0baced9886defcbdc8f65e951a414f51df86e022010715ee835a68f1c20e3be46b48b80e8f05d587c9edc562e7bf2fa307f21cff8014c695221023cbc2ad2dad9231a9e907a4a69dcfe2514d04db5a0fc5a903361fb892b16be8021027b766284e7c9db06628dd9481c6176dd94524c2317f7ca4e8f1ab549c9fe8da62103a9e76e199de14118b683187c1c7fcbf5427e8cc2c290d5daf1261a716742a69c53aeffffffffdfc3afe3f49543716276373812826f55b9dc4e9f2ee2c858cb0b5e19e33f7c9500000000fdfd00004730440220685655193c0dd894bc348bb5b8ac0247764784b947ab53b538a4f88008749f6402204a4b5912d558aa278a8ee3744ba74384c30420e8d2724ed13b35201fb013437301483045022100ae6da2282de47eb9d655b801b41d1494ccf995753104d9741a0d63bd4646eb1b0220607cbcbe76e6628fe902bf3ea6597400f878e9ef2302ff7ae4e62a70c95babaf014c695221023cbc2ad2dad9231a9e907a4a69dcfe2514d04db5a0fc5a903361fb892b16be8021027b766284e7c9db06628dd9481c6176dd94524c2317f7ca4e8f1ab549c9fe8da62103a9e76e199de14118b683187c1c7fcbf5427e8cc2c290d5daf1261a716742a69c53aeffffffff9de37111afcc701f30167f463c14467ffff8af317837e8b0644220610dcaacc501000000fdfd000047304402207b240fdcde83165df09dcb7b7e9f7fd768106ab648520b47e2d723e6263306cb02201f1f803e8f35a54aeb683d2d22e7215ee03e8a4a584c144a588a6ce0355fc85101483045022100f3ebeab2532d71945fdc945a8ca7b7e46107a0478754938cdf4f82d1a51561b302203ba1e1b33bf6e71032e34c0916f78bb6a333c2049a16b16642ab5638aa6204a6014c695221023c5d83e61fbb07fae23b1ef5600b44e068d79de7025b7c97b4a17103e2e65cf921032b873786d37b7769b1777f43081bd14b6f6d7f5ea26c2362860eda0b2a60116a2103e23f0e9748f618bd53b4b6c23c56714b031623691425c1b5c82c907fdc0f5e0c53aeffffffff554fbce7a6e82360095f213752d97ffa3fc6b1b600d298b72b5e261c83ca614b01000000fdfd000047304402207c9b7e46feedbd77143e81bb4c099cfe0db441e634307a9de2f70305fec2c381022051912c43a004ae2348b440013dd6218136800b89a3a4f1418ca4b27ffa40bf1001483045022100c38e31dfe2437d2fdfeab15a7533c1d3fcb6a7c8d26e5498695cccc43001296c022072e708c8e3a4dbc64dd3a6eac8e2fc0d0a3d55ba746e972b2a5d8275b556ec1d014c695221023d69319c33f4ad28b6518744798ee2a77116d8495785c1cc84d6f219d85ef4f62102678747b4b9aeed0abdc55e02bec75e1eb74fdcd11fee8785ae989ab7b5976c302102882b1281ed00e9b3629f16752f0436932941ea7065f42d4f5725cf4cf153932153aeffffffff0200a3e111000000001976a91442be95374aed1876e1fa0a8ec6a2fa0b0fe1214088ac3dc648000000000017a91442118ab92bfdcfcc884e5edf3063e90f51a3d2488700000000");
    let raw_reftx = hex!("0100000002069dc300e8b6e7ab2bf730031d6a4c992c832901d9d5d812eaf6da4ebc741d40000000006a47304402204a02661c79ff20dec99fc96e7a2002ff8635094536a1b5a0029b6c5dcf9e2c0c02207f9e27917c9d95b9abcb36c3b92bc73cef481f4af37a0a4ea38b3c50c7b8f285012102f7714daa4075cd5d6b72a0e2f1224bb17df25e39b2b39a219a60ee4f8f32c00affffffff7ed464e27690f523437bdd4bdb3a2297ec01f04e135997e0136887ab83e7cec8020000006a473044022030f37e9eac368ad3c39ee8bad572c4fd89db0bd7da02366315053ad434dcf564022010647fa8c2e14c26e174d2fed880fb723ee64c72f460d883018f364701307e5c01210355239b80f3b7a2112edaf5b7fb48dc933f2a26ec359be90e32082163f1b57759ffffffff0294ff03010000000017a91424334fe9a4bb4bffdc2bc0d2e618625070f8362487f2ca0100000000001976a9147196755f5991d8595ed4f227f10fcc62fcd979d888ac00000000");

    println!("\n\n======== sighash_p2sh_multisig_2x3:\n");
    vrfy_pks(&raw_tx, 0, &raw_reftx);
}
fn test_sighash_p2wsh_multisig_2x2() {
    //The spending transaction is
    //bitcoin-cli getrawtransaction 2bb157363e7a62d70b92082a9b2c9bb6f329154f816b8d239bd58c35c789a96a  3
    //input 0 (the only input)
    //ScriptPubkey from its Witness data is:
    //bitcoin-cli decodescript 52210289da5da9d3700156db2d01e6362491733f6c886971791deda74b4e9d707190b2210323c437f30384498be79df2990ce5a8de00844e768c0ccce914335b6c26adea7352ae
    //its ASM is 2 0289da5da9d3700156db2d01e6362491733f6c886971791deda74b4e9d707190b2 0323c437f30384498be79df2990ce5a8de00844e768c0ccce914335b6c26adea73 2 OP_CHECKMULTISIG
    let raw_tx = hex!("010000000001011b9eb4122976fad8f809ee4cea8ac8d1c5b6b8e0d0f9f93327a5d78c9a3945280000000000ffffffff02ba3e0d00000000002200201c3b09401aaa7c9709d118a75d301bdb2180fb68b2e9b3ade8ad4ff7281780cfa586010000000000220020a41d0d894799879ca1bd88c1c3f1c2fd4b1592821cc3c5bfd5be5238b904b09f040047304402201c7563e876d67b5702aea5726cd202bf92d0b1dc52c4acd03435d6073e630bac022032b64b70d7fba0cb8be30b882ea06c5f8ec7288d113459dd5d3e294214e2c96201483045022100f532f7e3b8fd01a0edc86de4870db4e04858964d0a609df81deb99d9581e6c2e02206d9e9b6ab661176be8194faded62f518cdc6ee74dba919e0f35d77cff81f38e5014752210289da5da9d3700156db2d01e6362491733f6c886971791deda74b4e9d707190b2210323c437f30384498be79df2990ce5a8de00844e768c0ccce914335b6c26adea7352ae00000000");
    //For the witness transaction sighash computation, we need its referenced output's value from the original transaction:
    //bitcoin-cli getrawtransaction 2845399a8cd7a52733f9f9d0e0b8b6c5d1c88aea4cee09f8d8fa762912b49e1b  3
    let raw_reftx = hex!("02000000000101828b350cf855b1a52b23a17dc89ed4e99e6d70503e1e1519945f75e19e7617c50000000000fdffffff0230c60e0000000000220020781ada670a98cfb276c6d2a78bbf21eb8f3617f4c2288cb16f5ad8741b5d83dd809698000000000016001449176d383a51877682b0f80e24776c015b2fa6d502473044022064b1047b43707baef72e69796c18340cfe74ff3fdb720bd8d6d814df2c61224802204c2c00fe218461eb84f01a885b90f73b90caae7b25e906e43618916cd7bd3a270121033d0f4a852ee6b3cec7bea4296bf6e4a88510fb5ac6da80b95fa8bb3bfc9fd1bb5fae0a00");

    println!("\n\n======== sighash_p2wsh_multisig_2x2:\n");
    vrfy_pks(&raw_tx, 0, &raw_reftx);
}

fn test_sighash_p2ms_multisig_2x3() {
    //Spending tx:
    //bitcoin-cli getrawtransaction 949591ad468cef5c41656c0a502d9500671ee421fadb590fbc6373000039b693  3
    //Inp 0 scriptSig has 2 sigs
    let raw_tx = hex!("010000000110a5fee9786a9d2d72c25525e52dd70cbd9035d5152fac83b62d3aa7e2301d58000000009300483045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4ed800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d150daedcf36787601483045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b86cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7cb46d8b7e0fdc4801ffffffff0180a21900000000001976a914971802edf585cdbc4e57017d6e5142515c1e502888ac00000000");
    //Original transaction:
    //bitcoin-cli getrawtransaction 581d30e2a73a2db683ac2f15d53590bd0cd72de52555c2722d9d6a78e9fea510  3
    let raw_reftx = hex!("01000000014563f26698c0ea3ebd85d4767457370d7e2ebbe922a7736dbf70e1d0f8a9aa9c000000008a473044022039294d5c8843a6776d4a2032cf03549f41c634ba5e65898c7816973919e485b902205af1f61f6d7d6a5f32cbe46676303c141fe499288b1be0d8f0c4e80d4c0ecb5701410454ffbc96ef3c26acffa431066915308865d990e044c507e0ab3d26af34a8ba5b4cb3028fe7c91926bb8be47d652dc70ab300e3022f8259db5f79306b601fc66effffffff0190c9190000000000c9524104d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a18314578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a24104ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d012dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb14104b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e753ae00000000");

    println!("\n\n======== sighash_p2ms_multisig_2x3:\n");
    vrfy_pks(&raw_tx, 0, &raw_reftx);
}

fn test_sighash_p2tr_multisig_1x2() {
    //Spending tx:
    //bitcoin-cli getrawtransaction 2eb8dbaa346d4be4e82fe444c2f0be00654d8cfd8c4a9a61b11aeaab8c00b272  3
    //Inp 0
    //tapscript: "c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabae OP_CHECKSIG b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333c OP_CHECKSIGADD 1 OP_NUMEQUAL"
    let raw_tx = hex!("010000000001022373cf02ce7df6500ae46a4a0fbbb1b636d2debed8f2df91e2415627397a34090000000000fdffffff88c23d928893cd3509845516cf8411b7cab2738c054cc5ce7e4bde9586997c770000000000fdffffff0200000000000000002b6a29676d20746170726f6f7420f09fa5952068747470733a2f2f626974636f696e6465766b69742e6f72676e9e1100000000001976a91405070d0290da457409a37db2e294c1ffbc52738088ac04410adf90fd381d4a13c3e73740b337b230701189ed94abcb4030781635f035e6d3b50b8506470a68292a2bc74745b7a5732a28254b5f766f09e495929ec308090b01004620c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c21c0000000000000000000000000000000000000000000000000000000000000000104414636070d21adc8280735383102f7a0f5978cea257777a23934dd3b458b79bf388aca218e39e23533a059da173e402c4fc5e3375e1f839efb22e9a5c2a815b07301004620c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c21c0000000000000000000000000000000000000000000000000000000000000000100000000");
    //Original transaction:
    //bitcoin-cli getrawtransaction 09347a39275641e291dff2d8beded236b6b1bb0f4a6ae40a50f67dce02cf7323  3
    let raw_reftx_vec : Vec<&[u8]> = vec![&hex!("010000000409cc8928f1d3ea4855dedbff8b783e3379735817b072df569776b5c5187d09ca010000006b483045022100a885cea8709cbb93b8311bf2fd5a30ff3e9fc02459652ebb040f47efc70cf51e02202194d53c2fe26cafcdf5748722949a275faf8575d15e2967d1bd3010d652c21b012102682e5ebd58a7d62a87b0490572776e4bb87dc868fb06419d8f33fe41c21160f9ffffffff0fbd54556226c210849929c0c50c00fc472ab4448be0333aa59f335c4e5a088b010000006b483045022100c4c368a8696a200e2d815c0d7cba690e415e3af6f6a0472b28c292ab85ffaa7002207911811c71ac927c48c47797fe8790a0d7ba172a7005ee8036e70e481909a375012102682e5ebd58a7d62a87b0490572776e4bb87dc868fb06419d8f33fe41c21160f9ffffffffa5091f20a2f91e56811e0d979b2dd7126c58dcd2d767d379e25c0a09c3c526fb010000006a473044022046bf081055f3409cee71cedb396a28060f1166195130cb8bedd6a13ecd1f6beb0220602ebd6e0a7b2c39bcfb59b42035dc246ec2a87e2e9f4b71ffa13feb15167615012102682e5ebd58a7d62a87b0490572776e4bb87dc868fb06419d8f33fe41c21160f9ffffffffb2c3b6434a7bda252db8aeb975ea5ca58da36a461545bb634dddadf5e35c6607010000006b483045022100a0466b24f77b68c54748d1c9ac43559eb91f952928b3fe28e452e619f814f23d022003853b255707400301cedd7922256d623ba2fc60d2734f19f79b2c6f0f61c3d4012102682e5ebd58a7d62a87b0490572776e4bb87dc868fb06419d8f33fe41c21160f9ffffffff01273f110000000000225120667bdd93c7c029767fd516d2ea292624b938fefefa175ac9f1220cf508963ff300000000"), &hex!("02000000000101fe9d111c806dbf9fa4f03869a42ff81972691b86db5c3ef89381456b4422d3be0000000000ffffffff023075000000000000225120667bdd93c7c029767fd516d2ea292624b938fefefa175ac9f1220cf508963ff30000000000000000116a0f676d20746170726f6f7420f09fa59502473044022001ce176bf7357e12a873b4e439d53eb02f1a642a043a6b7e9e5ae46d0d152f8c02204d603e93f49205624eb56c686fc759cc8d11000f4df76c24bda62d790f13d1ff012102e484e53bcce92e801a29454dae07812d6999bf1133aca94c8b03c65b56bdd08d00000000")];

    println!("\n\n======== sighash_p2tr_multisig_1x2\n");
    vrfy_pks_tr(&raw_tx, 0, raw_reftx_vec);
}

fn test_sighash_p2tr_multisig_2x2() {
    //Spending tx:
    //bitcoin-cli getrawtransaction 905ecdf95a84804b192f4dc221cfed4d77959b81ed66013a7e41a6e61e7ed530 3
    //Inp 0
    //tapscript: "febe583fa77e49089f89b78fa8c116710715d6e40cc5f5a075ef1681550dd3c4 OP_CHECKSIGVERIFY d0fa46cb883e940ac3dc5421f05b03859972639f51ed2eccbf3dc5a62e2e1b15 OP_CHECKSIG"
    let raw_tx = hex!("02000000000101b41b20295ac85fd2ae3e3d02900f1a1e7ddd6139b12e341386189c03d6f5795b0000000000fdffffff0100000000000000003c6a3a546878205361746f7368692120e2889e2f32316d696c20466972737420546170726f6f74206d756c7469736967207370656e64202d426974476f044123b1d4ff27b16af4b0fcb9672df671701a1a7f5a6bb7352b051f461edbc614aa6068b3e5313a174f90f3d95dc4e06f69bebd9cf5a3098fde034b01e69e8e788901400fd4a0d3f36a1f1074cb15838a48f572dc18d412d0f0f0fc1eeda9fa4820c942abb77e4d1a3c2b99ccf4ad29d9189e6e04a017fe611748464449f681bc38cf394420febe583fa77e49089f89b78fa8c116710715d6e40cc5f5a075ef1681550dd3c4ad20d0fa46cb883e940ac3dc5421f05b03859972639f51ed2eccbf3dc5a62e2e1b15ac41c02e44c9e47eaeb4bb313adecd11012dfad435cd72ce71f525329f24d75c5b9432774e148e9209baf3f1656a46986d5f38ddf4e20912c6ac28f48d6bf747469fb100000000");
    //Original transaction:
    //bitcoin-cli getrawtransaction 5b79f5d6039c188613342eb13961dd7d1e1a0f90023d3eaed25fc85a29201bb4 3
    let raw_reftx_vec: Vec<&[u8]>  = vec![&hex!("0200000000010140b84131c5c582290126bbd8b8e2e5bbd7c2681a4b01314f1b874ea1b5fdf81c0000000000ffffffff014c1d0000000000002251202fcad7470279652cc5f88b8908678d6f4d57af5627183b03fc8404cb4e16d88902473044022066d6939ea701db5d306fb948aea64af196ae52fc34d62c2e7992f62cdabc791402200abdac6766105457ceabcbe55a2d33f064d515210085f7af1248d273442e2b2a012103476f0d6a85ced4a85b08cbabbff28564a1ba31091b38f10b167f4fe1e1c9c4f900d40a00")];

    println!("\n\n======== sighash_p2tr_multisig_2x2\n");
    vrfy_pks_tr(&raw_tx, 0, raw_reftx_vec);
}

/// Finds the valid PubKeys in a verified segwit multisig transaction input that spends a p2wsh output with "witness_v0_scripthash" scriptPubKey.type
///
/// # Arguments
///
/// * `raw_tx` - spending tx hex
/// * `inp_idx` - spending tx input index
/// * `value` - ref tx output value in sats
fn vrfy_pks(mut raw_tx: &[u8], inp_idx: usize, mut raw_reftx: &[u8]) -> Vec<bitcoin::PublicKey> {
    let tx: bitcoin::Transaction =
        bitcoin::consensus::Decodable::consensus_decode(&mut raw_tx).unwrap();
    let reftx: bitcoin::Transaction =
        bitcoin::consensus::Decodable::consensus_decode(&mut raw_reftx).unwrap();
    let vout: usize = tx.input[inp_idx].previous_output.vout.try_into().unwrap();
    let script_pubkey = &reftx.output[vout].script_pubkey;
    let interpreter = miniscript::Interpreter::from_txdata(
        script_pubkey,
        &tx.input[inp_idx].script_sig,
        &tx.input[inp_idx].witness,
        Sequence::ZERO,
        LockTime::ZERO,
    )
    .unwrap();
    println!("is_p2pk()\t= {}", script_pubkey.is_p2pk());
    println!("is_p2pkh()\t= {}", script_pubkey.is_p2pkh());
    println!("is_v0_p2wpkh()\t= {}", script_pubkey.is_v0_p2wpkh());
    println!("is_v0_p2wsh()\t= {}", script_pubkey.is_v0_p2wsh());
    println!("is_v1_p2tr()\t= {}", script_pubkey.is_v1_p2tr());
    println!("is_p2sh()\t= {}", script_pubkey.is_p2sh());
    println!(
        "legacy {} script_code {:?}",
        interpreter.is_legacy(),
        interpreter
            .inferred_descriptor()
            .unwrap()
            .script_code()
            .unwrap()
    );

    let secp = Secp256k1::new();
    let outs_vec: Vec<bitcoin::TxOut>;
    if interpreter.is_segwit_v0() {
        //prevouts need to be aligned with inputs since miniscript::Interpreter::verify_sig looks for the prevout at inp_idx
        outs_vec = vec![reftx.output[vout].clone(); inp_idx + 1];
    } else {
        outs_vec = vec![];
    }
    let prevouts = sighash::Prevouts::All::<bitcoin::TxOut>(&outs_vec);
    let mut verified_pk_vec = vec![];
    let iter = interpreter.iter_custom(Box::new(|key_sig: &KeySigPair| {
        let res = interpreter.verify_sig(&secp, &tx, inp_idx, &prevouts, key_sig);
        let (pk, ecdsa_sig) = key_sig.as_ecdsa().expect("Ecdsa Sig");
        //println!(" tx {:?}", &tx);
        println!("{}<->\t{}", pk, ecdsa_sig.sig);
        if res {
            verified_pk_vec.push(pk);
        }
        res
    }));

    for _ in iter {}
    if verified_pk_vec.len() > 0 {
        println!(
            "\nsuccessfully verified {} pks: {}",
            verified_pk_vec.len(),
            verified_pk_vec
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        );
    } else {
        println!("\n*** failed to verify pks");
    }

    verified_pk_vec
}

fn vrfy_pks_tr(
    mut raw_tx: &[u8],
    inp_idx: usize,
    raw_reftx_vec: Vec<&[u8]>,
) -> Vec<bitcoin::key::XOnlyPublicKey> {
    let tx: bitcoin::Transaction =
        bitcoin::consensus::Decodable::consensus_decode(&mut raw_tx).unwrap();
    let mut reftx_vec: Vec<bitcoin::Transaction> = vec![];
    for raw_reftx in raw_reftx_vec {
        let mut raw: &[u8] = raw_reftx;
        let reftx = bitcoin::consensus::Decodable::consensus_decode(&mut raw).unwrap();
        reftx_vec.push(reftx);
    }
    let vout: usize = tx.input[inp_idx].previous_output.vout.try_into().unwrap();
    let script_pubkey = &reftx_vec[inp_idx].output[vout].script_pubkey;
    let interpreter = miniscript::Interpreter::from_txdata(
        script_pubkey,
        &tx.input[inp_idx].script_sig,
        &tx.input[inp_idx].witness,
        Sequence::ZERO,
        LockTime::ZERO,
    )
    .unwrap();
    println!(
        "is_v1_p2tr = {} is_taproot_v1_key_spend = {} is_taproot_v1_script_spend = {}",
        script_pubkey.is_v1_p2tr(),
        interpreter.is_taproot_v1_key_spend(),
        interpreter.is_taproot_v1_script_spend()
    );
    println!(
        "inferred_descriptor {:?}",
        interpreter.inferred_descriptor_string()
    );

    let secp = Secp256k1::new();
    let mut outs_vec: Vec<bitcoin::TxOut> = vec![];
    for (i, reftx) in reftx_vec.iter().enumerate() {
        let vout: usize = tx.input[i].previous_output.vout.try_into().unwrap();
        outs_vec.push(reftx.output[vout].clone());
    }
    let prevouts = sighash::Prevouts::All::<bitcoin::TxOut>(&outs_vec);
    let mut verified_pk_vec = vec![];
    let iter = interpreter.iter_custom(Box::new(|key_sig: &KeySigPair| {
        let res = interpreter.verify_sig(&secp, &tx, inp_idx, &prevouts, key_sig);
        let (pk, sig) = key_sig.as_schnorr().expect("Schnorr Sig");
        //println!(" tx {:?}", &tx);
        println!("{}<->\t{} {}", pk, sig.sig, res);
        if res {
            verified_pk_vec.push(pk);
        }
        res
    }));

    for _ in iter {}
    if verified_pk_vec.len() > 0 {
        println!(
            "\nsuccessfully verified {} pks: {}",
            verified_pk_vec.len(),
            verified_pk_vec
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        );
    } else {
        println!("\n*** failed to verify pks");
    }
    verified_pk_vec
}
