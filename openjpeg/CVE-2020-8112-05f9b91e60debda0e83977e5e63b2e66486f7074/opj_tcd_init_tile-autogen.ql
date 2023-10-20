/**
 * @name openjpeg-05f9b91e60debda0e83977e5e63b2e66486f7074-opj_tcd_init_tile
 * @id cpp/openjpeg/05f9b91e60debda0e83977e5e63b2e66486f7074/opj-tcd-init-tile
 * @description openjpeg-05f9b91e60debda0e83977e5e63b2e66486f7074-src/lib/openjp2/tcd.c-opj_tcd_init_tile CVE-2020-8112
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmanager_722, ExprStmt target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmanager_722
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Integer overflow\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vmanager_722, ExprStmt target_8) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("opj_event_msg")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vmanager_722
		and target_1.getArgument(1).(Literal).getValue()="1"
		and target_1.getArgument(2).(StringLiteral).getValue()="Integer overflow\n"
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_3(Parameter vmanager_722, ExprStmt target_9) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmanager_722
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Integer overflow\n"
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Variable vl_br_prc_y_end_744, ExprStmt target_10) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_br_prc_y_end_744
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("OPJ_UINT32")
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_6(Variable vl_res_732, Variable vl_pdx_739, BinaryBitwiseOperation target_6) {
		target_6.getLeftOperand().(FunctionCall).getTarget().hasName("opj_int_ceildivpow2")
		and target_6.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="x1"
		and target_6.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_res_732
		and target_6.getLeftOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_pdx_739
		and target_6.getRightOperand().(VariableAccess).getTarget()=vl_pdx_739
		and target_6.getParent().(AssignExpr).getRValue() = target_6
}

predicate func_7(Variable vl_res_732, Variable vl_pdy_739, Variable vl_br_prc_y_end_744, BinaryBitwiseOperation target_7) {
		target_7.getLeftOperand().(FunctionCall).getTarget().hasName("opj_int_ceildivpow2")
		and target_7.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="y1"
		and target_7.getLeftOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_res_732
		and target_7.getLeftOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_pdy_739
		and target_7.getRightOperand().(VariableAccess).getTarget()=vl_pdy_739
		and target_7.getParent().(AssignExpr).getRValue() = target_7
		and target_7.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_br_prc_y_end_744
}

predicate func_8(Parameter vmanager_722, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmanager_722
		and target_8.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_8.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Size of tile data exceeds system limits\n"
}

predicate func_9(Parameter vmanager_722, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("opj_event_msg")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmanager_722
		and target_9.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_9.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Not enough memory for tile resolutions\n"
}

predicate func_10(Variable vl_res_732, Variable vl_pdy_739, Variable vl_br_prc_y_end_744, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ph"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_res_732
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="y0"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_res_732
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="y1"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_res_732
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="0"
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vl_br_prc_y_end_744
		and target_10.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vl_pdy_739
}

from Function func, Parameter vmanager_722, Variable vl_res_732, Variable vl_pdx_739, Variable vl_pdy_739, Variable vl_br_prc_y_end_744, BinaryBitwiseOperation target_6, BinaryBitwiseOperation target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10
where
not func_0(vmanager_722, target_8)
and not func_3(vmanager_722, target_9)
and not func_4(vl_br_prc_y_end_744, target_10)
and func_6(vl_res_732, vl_pdx_739, target_6)
and func_7(vl_res_732, vl_pdy_739, vl_br_prc_y_end_744, target_7)
and func_8(vmanager_722, target_8)
and func_9(vmanager_722, target_9)
and func_10(vl_res_732, vl_pdy_739, vl_br_prc_y_end_744, target_10)
and vmanager_722.getType().hasName("opj_event_mgr_t *")
and vl_res_732.getType().hasName("opj_tcd_resolution_t *")
and vl_pdx_739.getType().hasName("OPJ_UINT32")
and vl_pdy_739.getType().hasName("OPJ_UINT32")
and vl_br_prc_y_end_744.getType().hasName("OPJ_INT32")
and vmanager_722.getParentScope+() = func
and vl_res_732.getParentScope+() = func
and vl_pdx_739.getParentScope+() = func
and vl_pdy_739.getParentScope+() = func
and vl_br_prc_y_end_744.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
