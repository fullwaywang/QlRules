/**
 * @name libass-676f9dc5b52ef406c5527bdadbcb947f11392929-outline_transform_2d
 * @id cpp/libass/676f9dc5b52ef406c5527bdadbcb947f11392929/outline-transform-2d
 * @description libass-676f9dc5b52ef406c5527bdadbcb947f11392929-libass/ass_outline.c-outline_transform_2d CVE-2020-26682
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vv_243, Parameter voutline_230, ExprStmt target_1, ArrayExpr target_2, NotExpr target_3, ArrayExpr target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("fabs")
		and target_0.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vv_243
		and target_0.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getValue()="268435455"
		and target_0.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("fabs")
		and target_0.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vv_243
		and target_0.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getValue()="268435455"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("outline_free")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voutline_230
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getArrayBase().(VariableAccess).getLocation())
		and target_3.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vv_243, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vv_243
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="x"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="y"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
}

predicate func_2(Variable vv_243, ArrayExpr target_2) {
		target_2.getArrayBase().(VariableAccess).getTarget()=vv_243
		and target_2.getArrayOffset().(Literal).getValue()="0"
}

predicate func_3(Parameter voutline_230, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("outline_alloc")
		and target_3.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voutline_230
		and target_3.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="n_points"
		and target_3.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="n_segments"
}

predicate func_4(Parameter voutline_230, ArrayExpr target_4) {
		target_4.getArrayBase().(PointerFieldAccess).getTarget().getName()="points"
		and target_4.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutline_230
}

from Function func, Variable vv_243, Parameter voutline_230, ExprStmt target_1, ArrayExpr target_2, NotExpr target_3, ArrayExpr target_4
where
not func_0(vv_243, voutline_230, target_1, target_2, target_3, target_4)
and func_1(vv_243, target_1)
and func_2(vv_243, target_2)
and func_3(voutline_230, target_3)
and func_4(voutline_230, target_4)
and vv_243.getType().hasName("double[2]")
and voutline_230.getType().hasName("ASS_Outline *")
and vv_243.getParentScope+() = func
and voutline_230.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
