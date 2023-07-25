/**
 * @name wireshark-b5b02f2a9b8772d8814096f86c60a32889d61f2c-dissect_transform
 * @id cpp/wireshark/b5b02f2a9b8772d8814096f86c60a32889d61f2c/dissect-transform
 * @description wireshark-b5b02f2a9b8772d8814096f86c60a32889d61f2c-epan/dissectors/packet-isakmp.c-dissect_transform CVE-2019-5719
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdecr_3911, LogicalAndExpr target_4, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vdecr_3911
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_0.getCondition().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdecr_3911, LogicalAndExpr target_4, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ike_encr_alg"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdecr_3911
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_2(Variable vdecr_3911, LogicalAndExpr target_4, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ike_encr_keylen"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdecr_3911
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_3(Variable vdecr_3911, LogicalAndExpr target_4, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ike_hash_alg"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdecr_3911
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_4(LogicalAndExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
}

from Function func, Variable vdecr_3911, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, LogicalAndExpr target_4
where
not func_0(vdecr_3911, target_4, target_1)
and func_1(vdecr_3911, target_4, target_1)
and func_2(vdecr_3911, target_4, target_2)
and func_3(vdecr_3911, target_4, target_3)
and func_4(target_4)
and vdecr_3911.getType().hasName("decrypt_data_t *")
and vdecr_3911.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
