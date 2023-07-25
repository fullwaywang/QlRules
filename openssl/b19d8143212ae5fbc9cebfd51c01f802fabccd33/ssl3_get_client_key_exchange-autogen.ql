/**
 * @name openssl-b19d8143212ae5fbc9cebfd51c01f802fabccd33-ssl3_get_client_key_exchange
 * @id cpp/openssl/b19d8143212ae5fbc9cebfd51c01f802fabccd33/ssl3-get-client-key-exchange
 * @description openssl-b19d8143212ae5fbc9cebfd51c01f802fabccd33-ssl3_get_client_key_exchange CVE-2015-1787
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vn_2072, Variable valg_k_2073) {
	exists(IfStmt target_1 |
		target_1.getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=valg_k_2073
		and target_1.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8"
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vn_2072
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1")
}

predicate func_5(Variable vi_2071, Variable vn_2072, Variable vp_2074) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_2071
		and target_5.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_2074
		and target_5.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_5.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_2074
		and target_5.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_5.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_2074
		and target_5.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_5.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vn_2072)
}

predicate func_6(Variable vi_2071, Variable vn_2072) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_2071
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_6.getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vn_2072)
}

predicate func_7(Variable val_2071, Variable vskey_2253) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=val_2071
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="40"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vskey_2253
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="28"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="dh"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="pkey"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_14(Variable vn_2072, Variable valg_k_2073) {
	exists(BitwiseAndExpr target_14 |
		target_14.getLeftOperand().(VariableAccess).getTarget()=valg_k_2073
		and target_14.getRightOperand().(BitwiseOrExpr).getValue()="14"
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="0"
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(VariableAccess).getTarget()=vn_2072
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen() instanceof ExprStmt
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getElse() instanceof ExprStmt
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vn_2072
		and target_14.getParent().(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vn_2072)
}

from Function func, Variable vi_2071, Variable val_2071, Variable vn_2072, Variable valg_k_2073, Variable vp_2074, Variable vdh_clnt_2081, Variable vclnt_pub_pkey_2089, Variable vskey_2253
where
not func_1(vn_2072, valg_k_2073)
and func_5(vi_2071, vn_2072, vp_2074)
and func_6(vi_2071, vn_2072)
and func_7(val_2071, vskey_2253)
and vi_2071.getType().hasName("int")
and val_2071.getType().hasName("int")
and vn_2072.getType().hasName("long")
and valg_k_2073.getType().hasName("unsigned long")
and func_14(vn_2072, valg_k_2073)
and vp_2074.getType().hasName("unsigned char *")
and vdh_clnt_2081.getType().hasName("DH *")
and vclnt_pub_pkey_2089.getType().hasName("EVP_PKEY *")
and vskey_2253.getType().hasName("EVP_PKEY *")
and vi_2071.getParentScope+() = func
and val_2071.getParentScope+() = func
and vn_2072.getParentScope+() = func
and valg_k_2073.getParentScope+() = func
and vp_2074.getParentScope+() = func
and vdh_clnt_2081.getParentScope+() = func
and vclnt_pub_pkey_2089.getParentScope+() = func
and vskey_2253.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
