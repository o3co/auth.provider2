# auth.provider2

公開面が取られても、攻撃者に token を発行させない OAuth 2.0 / OpenID Connect の provider。

**auth.provider2 は [auth.provider](https://github.com/o3co/auth.provider) と別の製品である。** auth.provider の module を元に作るが、契約、組み方、版の番号は自分のものを持つ。auth.provider2 の 0.x は、auth.provider の 0.x や 1.x と関係しない。

## 約束

- **公開面 (Front) が取られても、新しいログインには利用者の passkey が要る。** refresh は、そのログインに縛られた期限つきの委任である。
- **Front が取られても、client の token にはその client の秘密鍵が要る。**
- さらに、導入が透明性ログと監視者を足すと、取られた Core の偽造の発行は、受領証を確かめる受け手に通らず、監視者の判定でその Core の世代が止まる。最初の版はこの約束の契約までを持ち、実装は後から入る。

どの約束も、書いた条件の下で成り立つ。provider は、起動のたびに、今の組がどの条件を満たすかを報告する。

## 状態

作っている途中。まだ何も公開していない。最初の版 0.1.0 は、設計と実装が収束したときに公開する。

## 配置

- `modules/<group>/<name>`: provider の package。1 つの関心に 1 つ。各 module の README がその契約である。
- `sdk/` (これから): 受け手で動く package (ログイン画面の SDK と、RP の確かめの部品)。依存してよいのは protocol の package だけで、provider と同じ版で一緒に出す。

## ライセンス

[Apache License 2.0](LICENSE)
