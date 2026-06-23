package klon

// GrantManagementAction は grant_management_action パラメータの値を表す。
// KLON は 1 ユーザー × 1 クライアントにつき有効な同意 (グラント) を 1 つ管理し、
// この値で既存グラントの扱いを指定する。
type GrantManagementAction string

const (
	// GrantManagementCreate は既存が無ければ新規グラントを作成する。
	// 既存があり要求を内包していれば再利用し、足りなければ同意を求める。
	GrantManagementCreate GrantManagementAction = "create"
	// GrantManagementReplace は既存グラントを要求権限で置換する
	// (以前の権限は保持されない)。常に同意が必要となる。
	GrantManagementReplace GrantManagementAction = "replace"
	// GrantManagementMerge は既存グラントとの差分を追加する。
	// 差分があるときだけ同意が必要となる。
	GrantManagementMerge GrantManagementAction = "merge"
)
