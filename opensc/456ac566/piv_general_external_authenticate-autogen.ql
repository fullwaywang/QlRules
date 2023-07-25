/**
 * @name opensc-456ac566-piv_general_external_authenticate
 * @id cpp/opensc/456ac566/piv-general-external-authenticate
 * @description opensc-456ac566-src/libopensc/card-piv.c-piv_general_external_authenticate CVE-2021-42782
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrbuf_1850, BlockStmt target_2, ExprStmt target_3) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrbuf_1850
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="124"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbody_1854, BlockStmt target_2, NotExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=vbody_1854
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sc_do_log")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="Invalid Challenge Data response of NULL\n"
}

predicate func_3(Variable vrbuf_1850, Variable vbody_1854, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbody_1854
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sc_asn1_find_tag")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrbuf_1850
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(HexLiteral).getValue()="124"
}

from Function func, Variable vrbuf_1850, Variable vbody_1854, NotExpr target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vrbuf_1850, target_2, target_3)
and func_1(vbody_1854, target_2, target_1)
and func_2(target_2)
and func_3(vrbuf_1850, vbody_1854, target_3)
and vrbuf_1850.getType().hasName("u8[4096]")
and vbody_1854.getType().hasName("const u8 *")
and vrbuf_1850.getParentScope+() = func
and vbody_1854.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
