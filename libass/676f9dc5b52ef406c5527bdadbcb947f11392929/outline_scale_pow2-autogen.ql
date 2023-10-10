/**
 * @name libass-676f9dc5b52ef406c5527bdadbcb947f11392929-outline_scale_pow2
 * @id cpp/libass/676f9dc5b52ef406c5527bdadbcb947f11392929/outline-scale-pow2
 * @description libass-676f9dc5b52ef406c5527bdadbcb947f11392929-libass/ass_outline.c-outline_scale_pow2 CVE-2020-26682
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vscale_ord_x_205, AddExpr target_4, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vscale_ord_x_205
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int32_t")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vscale_ord_x_205
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="32"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getType().hasName("int32_t")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vscale_ord_x_205
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vscale_ord_x_205
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vscale_ord_x_205
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(UnaryMinusExpr).getValue()="-32"
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vscale_ord_x_205
		and target_0.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(UnaryMinusExpr).getValue()="-32"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vscale_ord_y_205, AddExpr target_5, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vscale_ord_y_205
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int32_t")
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vscale_ord_y_205
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="32"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getType().hasName("int32_t")
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vscale_ord_y_205
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vscale_ord_y_205
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vscale_ord_y_205
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(UnaryMinusExpr).getValue()="-32"
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vscale_ord_y_205
		and target_1.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(UnaryMinusExpr).getValue()="-32"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_1)
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter voutline_204, ExprStmt target_6, NotExpr target_7, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int32_t")
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("int32_t")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("outline_clear")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voutline_204
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_2)
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(Parameter voutline_204, Variable vpt_217, Variable vi_218, NotExpr target_7, ArrayExpr target_8, ArrayExpr target_9, PostfixIncrExpr target_10) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("abs")
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="x"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpt_217
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_218
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int32_t")
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("abs")
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="y"
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpt_217
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_218
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int32_t")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("outline_free")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voutline_204
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_7.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_8.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_9.getArrayBase().(VariableAccess).getLocation())
		and target_10.getOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vscale_ord_x_205, AddExpr target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vscale_ord_x_205
		and target_4.getAnOperand().(Literal).getValue()="32"
}

predicate func_5(Parameter vscale_ord_y_205, AddExpr target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vscale_ord_y_205
		and target_5.getAnOperand().(Literal).getValue()="32"
}

predicate func_6(Parameter voutline_204, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("outline_clear")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voutline_204
}

predicate func_7(Parameter voutline_204, NotExpr target_7) {
		target_7.getOperand().(FunctionCall).getTarget().hasName("outline_alloc")
		and target_7.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voutline_204
		and target_7.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="n_points"
		and target_7.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="n_segments"
}

predicate func_8(Parameter voutline_204, Variable vi_218, ArrayExpr target_8) {
		target_8.getArrayBase().(PointerFieldAccess).getTarget().getName()="points"
		and target_8.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutline_204
		and target_8.getArrayOffset().(VariableAccess).getTarget()=vi_218
}

predicate func_9(Variable vpt_217, Variable vi_218, ArrayExpr target_9) {
		target_9.getArrayBase().(VariableAccess).getTarget()=vpt_217
		and target_9.getArrayOffset().(VariableAccess).getTarget()=vi_218
}

predicate func_10(Variable vi_218, PostfixIncrExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vi_218
}

from Function func, Parameter voutline_204, Parameter vscale_ord_x_205, Parameter vscale_ord_y_205, Variable vpt_217, Variable vi_218, AddExpr target_4, AddExpr target_5, ExprStmt target_6, NotExpr target_7, ArrayExpr target_8, ArrayExpr target_9, PostfixIncrExpr target_10
where
not func_0(vscale_ord_x_205, target_4, func)
and not func_1(vscale_ord_y_205, target_5, func)
and not func_2(voutline_204, target_6, target_7, func)
and not func_3(voutline_204, vpt_217, vi_218, target_7, target_8, target_9, target_10)
and func_4(vscale_ord_x_205, target_4)
and func_5(vscale_ord_y_205, target_5)
and func_6(voutline_204, target_6)
and func_7(voutline_204, target_7)
and func_8(voutline_204, vi_218, target_8)
and func_9(vpt_217, vi_218, target_9)
and func_10(vi_218, target_10)
and voutline_204.getType().hasName("ASS_Outline *")
and vscale_ord_x_205.getType().hasName("int")
and vscale_ord_y_205.getType().hasName("int")
and vpt_217.getType().hasName("const ASS_Vector *")
and vi_218.getType().hasName("size_t")
and voutline_204.getParentScope+() = func
and vscale_ord_x_205.getParentScope+() = func
and vscale_ord_y_205.getParentScope+() = func
and vpt_217.getParentScope+() = func
and vi_218.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
