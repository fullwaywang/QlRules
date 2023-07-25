/**
 * @name openssl-2a40b7bc7b94dd7de897a74571e7024f0cf0d63b-check_chain_extensions
 * @id cpp/openssl/2a40b7bc7b94dd7de897a74571e7024f0cf0d63b/check-chain-extensions
 * @description openssl-2a40b7bc7b94dd7de897a74571e7024f0cf0d63b-check_chain_extensions CVE-2021-3450
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vret_486) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vret_486
		and target_0.getLesserOperand().(Literal).getValue()="0")
}

predicate func_1(Variable vret_486) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_486
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_486
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_2(Variable vret_486, Parameter vctx_455) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vret_486
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getAnOperand() instanceof EqualityOperation
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="param"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_455
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="32"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="error"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="41"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_486
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_3(Variable vnum_462, Variable vret_486, Parameter vctx_455) {
	exists(BitwiseAndExpr target_3 |
		target_3.getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="param"
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_455
		and target_3.getRightOperand().(Literal).getValue()="32"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnum_462
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_486
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("check_curve")
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vret_486
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_6(Variable vx_458) {
	exists(EqualityOperation target_6 |
		target_6.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="ex_flags"
		and target_6.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_458
		and target_6.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="16"
		and target_6.getAnOperand().(Literal).getValue()="0")
}

predicate func_7(Variable vx_458) {
	exists(EqualityOperation target_7 |
		target_7.getAnOperand().(PointerFieldAccess).getTarget().getName()="ex_pathlen"
		and target_7.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vx_458
		and target_7.getAnOperand().(UnaryMinusExpr).getValue()="-1")
}

predicate func_8(Variable vret_486) {
	exists(EqualityOperation target_8 |
		target_8.getAnOperand().(VariableAccess).getTarget()=vret_486
		and target_8.getAnOperand().(Literal).getValue()="0"
		and target_8.getParent().(IfStmt).getThen() instanceof ExprStmt)
}

from Function func, Variable vx_458, Variable vnum_462, Variable vret_486, Parameter vctx_455
where
not func_0(vret_486)
and not func_1(vret_486)
and not func_2(vret_486, vctx_455)
and func_3(vnum_462, vret_486, vctx_455)
and func_6(vx_458)
and func_7(vx_458)
and vx_458.getType().hasName("X509 *")
and vnum_462.getType().hasName("int")
and vret_486.getType().hasName("int")
and func_8(vret_486)
and vctx_455.getType().hasName("X509_STORE_CTX *")
and vx_458.getParentScope+() = func
and vnum_462.getParentScope+() = func
and vret_486.getParentScope+() = func
and vctx_455.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
