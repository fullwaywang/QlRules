/**
 * @name openjpeg-8f9cc62b3f9a1da9712329ddcedb9750d585505c-opj_tcd_init_tile
 * @id cpp/openjpeg/8f9cc62b3f9a1da9712329ddcedb9750d585505c/opj-tcd-init-tile
 * @description openjpeg-8f9cc62b3f9a1da9712329ddcedb9750d585505c-src/lib/openjp2/tcd.c-opj_tcd_init_tile CVE-2016-4797
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vl_data_size_681, BlockStmt target_2, ExprStmt target_3, RelationalOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vl_data_size_681
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vl_tilec_657, Variable vl_data_size_681, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(DivExpr).getLeftOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_1.getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vl_data_size_681
		and target_1.getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="y1"
		and target_1.getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tilec_657
		and target_1.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="y0"
		and target_1.getGreaterOperand().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tilec_657
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough memory for tile data\n"
		and target_2.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_3(Variable vl_tilec_657, Variable vl_data_size_681, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_data_size_681
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="x1"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tilec_657
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="x0"
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_tilec_657
}

from Function func, Variable vl_tilec_657, Variable vl_data_size_681, RelationalOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vl_data_size_681, target_2, target_3, target_1)
and func_1(vl_tilec_657, vl_data_size_681, target_2, target_1)
and func_2(target_2)
and func_3(vl_tilec_657, vl_data_size_681, target_3)
and vl_tilec_657.getType().hasName("opj_tcd_tilecomp_t *")
and vl_data_size_681.getType().hasName("OPJ_UINT32")
and vl_tilec_657.getParentScope+() = func
and vl_data_size_681.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
