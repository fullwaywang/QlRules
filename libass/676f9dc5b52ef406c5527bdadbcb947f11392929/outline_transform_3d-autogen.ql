/**
 * @name libass-676f9dc5b52ef406c5527bdadbcb947f11392929-outline_transform_3d
 * @id cpp/libass/676f9dc5b52ef406c5527bdadbcb947f11392929/outline-transform-3d
 * @description libass-676f9dc5b52ef406c5527bdadbcb947f11392929-libass/ass_outline.c-outline_transform_3d CVE-2020-26682
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vv_269, Variable vw_273, DivExpr target_13, MulExpr target_12) {
	exists(AssignMulExpr target_0 |
		target_0.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vv_269
		and target_0.getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getRValue().(VariableAccess).getTarget()=vw_273
		and target_13.getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getRValue().(VariableAccess).getLocation().isBefore(target_12.getRightOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vv_269, Variable vw_273, MulExpr target_11) {
	exists(AssignMulExpr target_1 |
		target_1.getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vv_269
		and target_1.getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_1.getRValue().(VariableAccess).getTarget()=vw_273)
}

predicate func_2(Parameter voutline_256, ArrayExpr target_14, ExprStmt target_15) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("fabs")
		and target_2.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0) instanceof ArrayExpr
		and target_2.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getValue()="268435455"
		and target_2.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("fabs")
		and target_2.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0) instanceof ArrayExpr
		and target_2.getCondition().(NotExpr).getOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getValue()="268435455"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("outline_free")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voutline_256
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_14.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter voutline_256, Variable vi_268, Variable vv_269, NotExpr target_16, ArrayExpr target_14, ArrayExpr target_17, MulExpr target_11) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="x"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="points"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutline_256
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_268
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lrint")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vv_269
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_16.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_17.getArrayOffset().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

/*predicate func_4(Variable vv_269, MulExpr target_11) {
	exists(ArrayExpr target_4 |
		target_4.getArrayBase().(VariableAccess).getTarget()=vv_269
		and target_4.getArrayOffset().(Literal).getValue()="0"
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lrint")
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof MulExpr)
}

*/
predicate func_5(Parameter voutline_256, Variable vi_268, Variable vv_269, ArrayExpr target_18, MulExpr target_12) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="y"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="points"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutline_256
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_268
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lrint")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vv_269
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_18.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_6(Variable vv_269, MulExpr target_12) {
	exists(ArrayExpr target_6 |
		target_6.getArrayBase().(VariableAccess).getTarget()=vv_269
		and target_6.getArrayOffset().(Literal).getValue()="1"
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lrint")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof MulExpr)
}

*/
predicate func_7(Variable vv_269, ArrayExpr target_7) {
		target_7.getArrayBase().(VariableAccess).getTarget()=vv_269
		and target_7.getArrayOffset().(Literal).getValue()="0"
}

predicate func_8(Variable vv_269, ArrayExpr target_8) {
		target_8.getArrayBase().(VariableAccess).getTarget()=vv_269
		and target_8.getArrayOffset().(Literal).getValue()="1"
}

predicate func_9(Variable vw_273, VariableAccess target_9) {
		target_9.getTarget()=vw_273
}

predicate func_10(Variable vw_273, VariableAccess target_10) {
		target_10.getTarget()=vw_273
}

predicate func_11(Variable vw_273, MulExpr target_11) {
		target_11.getLeftOperand() instanceof ArrayExpr
		and target_11.getRightOperand().(VariableAccess).getTarget()=vw_273
		and target_11.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lrint")
}

predicate func_12(Variable vw_273, MulExpr target_12) {
		target_12.getLeftOperand() instanceof ArrayExpr
		and target_12.getRightOperand().(VariableAccess).getTarget()=vw_273
		and target_12.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lrint")
}

predicate func_13(Variable vv_269, DivExpr target_13) {
		target_13.getLeftOperand().(Literal).getValue()="1"
		and target_13.getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vv_269
		and target_13.getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_13.getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0.1000000000000000056"
		and target_13.getRightOperand().(ConditionalExpr).getThen().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vv_269
		and target_13.getRightOperand().(ConditionalExpr).getThen().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_13.getRightOperand().(ConditionalExpr).getElse().(Literal).getValue()="0.1000000000000000056"
}

predicate func_14(Parameter voutline_256, Variable vi_268, ArrayExpr target_14) {
		target_14.getArrayBase().(PointerFieldAccess).getTarget().getName()="points"
		and target_14.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutline_256
		and target_14.getArrayOffset().(VariableAccess).getTarget()=vi_268
}

predicate func_15(Parameter voutline_256, ExprStmt target_15) {
		target_15.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="segments"
		and target_15.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutline_256
		and target_15.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="segments"
		and target_15.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="n_segments"
}

predicate func_16(Parameter voutline_256, NotExpr target_16) {
		target_16.getOperand().(FunctionCall).getTarget().hasName("outline_alloc")
		and target_16.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voutline_256
		and target_16.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="n_points"
		and target_16.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="n_segments"
}

predicate func_17(Variable vi_268, ArrayExpr target_17) {
		target_17.getArrayOffset().(VariableAccess).getTarget()=vi_268
}

predicate func_18(Parameter voutline_256, Variable vi_268, ArrayExpr target_18) {
		target_18.getArrayBase().(PointerFieldAccess).getTarget().getName()="points"
		and target_18.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voutline_256
		and target_18.getArrayOffset().(VariableAccess).getTarget()=vi_268
}

from Function func, Parameter voutline_256, Variable vi_268, Variable vv_269, Variable vw_273, ArrayExpr target_7, ArrayExpr target_8, VariableAccess target_9, VariableAccess target_10, MulExpr target_11, MulExpr target_12, DivExpr target_13, ArrayExpr target_14, ExprStmt target_15, NotExpr target_16, ArrayExpr target_17, ArrayExpr target_18
where
not func_0(vv_269, vw_273, target_13, target_12)
and not func_1(vv_269, vw_273, target_11)
and not func_2(voutline_256, target_14, target_15)
and not func_3(voutline_256, vi_268, vv_269, target_16, target_14, target_17, target_11)
and not func_5(voutline_256, vi_268, vv_269, target_18, target_12)
and func_7(vv_269, target_7)
and func_8(vv_269, target_8)
and func_9(vw_273, target_9)
and func_10(vw_273, target_10)
and func_11(vw_273, target_11)
and func_12(vw_273, target_12)
and func_13(vv_269, target_13)
and func_14(voutline_256, vi_268, target_14)
and func_15(voutline_256, target_15)
and func_16(voutline_256, target_16)
and func_17(vi_268, target_17)
and func_18(voutline_256, vi_268, target_18)
and voutline_256.getType().hasName("ASS_Outline *")
and vi_268.getType().hasName("size_t")
and vv_269.getType().hasName("double[3]")
and vw_273.getType().hasName("double")
and voutline_256.getParentScope+() = func
and vi_268.getParentScope+() = func
and vv_269.getParentScope+() = func
and vw_273.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
