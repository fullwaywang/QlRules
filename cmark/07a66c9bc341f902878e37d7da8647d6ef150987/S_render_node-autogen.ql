/**
 * @name cmark-07a66c9bc341f902878e37d7da8647d6ef150987-S_render_node
 * @id cpp/cmark/07a66c9bc341f902878e37d7da8647d6ef150987/S-render-node
 * @description cmark-07a66c9bc341f902878e37d7da8647d6ef150987-src/commonmark.c-S_render_node CVE-2023-26485
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vtmp_172, ExprStmt target_39, VariableAccess target_1) {
		target_1.getTarget()=vtmp_172
		and target_39.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getLocation())
}

predicate func_2(Variable vtmp_172, VariableAccess target_2) {
		target_2.getTarget()=vtmp_172
}

predicate func_3(Variable vtmp_172, PointerFieldAccess target_40, VariableAccess target_3) {
		target_3.getTarget()=vtmp_172
		and target_3.getLocation().isBefore(target_40.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_4(Variable vtmp_172, ExprStmt target_39, VariableAccess target_4) {
		target_4.getTarget()=vtmp_172
		and target_39.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getLocation())
}

predicate func_5(Variable vtmp_172, ExprStmt target_35, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="prev"
		and target_5.getQualifier().(VariableAccess).getTarget()=vtmp_172
		and target_35.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getQualifier().(VariableAccess).getLocation())
}

predicate func_6(Variable vtmp_172, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="prev"
		and target_6.getQualifier().(VariableAccess).getTarget()=vtmp_172
}

predicate func_7(Variable vtmp_172, ExprStmt target_39, VariableAccess target_7) {
		target_7.getTarget()=vtmp_172
		and target_7.getLocation().isBefore(target_39.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation())
}

predicate func_8(Variable vtmp_172, ExprStmt target_39, VariableAccess target_8) {
		target_8.getTarget()=vtmp_172
		and target_39.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_8.getLocation())
}

predicate func_9(Function func, Literal target_9) {
		target_9.getValue()="1"
		and not target_9.getValue()="0"
		and target_9.getParent().(AssignAddExpr).getParent().(ExprStmt).getExpr() instanceof AssignAddExpr
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Parameter vrenderer_170, Parameter vnode_170, NotExpr target_31, ExprStmt target_42, EqualityOperation target_43, ExprStmt target_21) {
	exists(IfStmt target_10 |
		target_10.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="parent"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_170
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("cmark_node *")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="in_tight_list_item"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrenderer_170
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="tight"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="list"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="as"
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_10
		and target_10.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_31
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_42.getExpr().(VariableCall).getArgument(1).(VariableAccess).getLocation())
		and target_43.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_11(Function func) {
	exists(ValueFieldAccess target_11 |
		target_11.getTarget().getName()="tight"
		and target_11.getQualifier().(ValueFieldAccess).getTarget().getName()="list"
		and target_11.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="as"
		and target_11.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_11.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_11.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("cmark_node *")
		and target_11.getEnclosingFunction() = func)
}

*/
predicate func_12(Parameter vrenderer_170, Parameter vnode_170, EqualityOperation target_43, LogicalAndExpr target_44, ExprStmt target_39) {
	exists(IfStmt target_12 |
		target_12.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_12.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_170
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="in_tight_list_item"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrenderer_170
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="parent"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="tight"
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="list"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_43
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_39.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_13(Parameter vrenderer_170, LogicalAndExpr target_44, ExprStmt target_39) {
	exists(AssignExpr target_13 |
		target_13.getLValue().(PointerFieldAccess).getTarget().getName()="in_tight_list_item"
		and target_13.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrenderer_170
		and target_13.getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="parent"
		and target_13.getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("cmark_node *")
		and target_13.getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_13.getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_13.getRValue().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("cmark_node *")
		and target_13.getRValue().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="tight"
		and target_13.getRValue().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="list"
		and target_13.getRValue().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="as"
		and target_13.getRValue().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_13.getRValue().(LogicalAndExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_39.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_14(Parameter vnode_170, ExprStmt target_21, EqualityOperation target_45) {
	exists(ValueFieldAccess target_14 |
		target_14.getTarget().getName()="tight"
		and target_14.getQualifier().(ValueFieldAccess).getTarget().getName()="list"
		and target_14.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="as"
		and target_14.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_14.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_14.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_170
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_14.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_45.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_15(Parameter vrenderer_170, ExprStmt target_46) {
	exists(PointerFieldAccess target_15 |
		target_15.getTarget().getName()="list_number"
		and target_15.getQualifier().(VariableAccess).getTarget()=vrenderer_170
		and target_15.getQualifier().(VariableAccess).getLocation().isBefore(target_46.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_16(Variable vlist_number_173, Parameter vrenderer_170, ExprStmt target_38, ExprStmt target_47) {
	exists(AssignExpr target_16 |
		target_16.getLValue().(VariableAccess).getTarget()=vlist_number_173
		and target_16.getRValue().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="list_number"
		and target_16.getRValue().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrenderer_170
		and target_16.getLValue().(VariableAccess).getLocation().isBefore(target_38.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
		and target_47.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getRValue().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_17(PointerFieldAccess target_48, Function func) {
	exists(IfStmt target_17 |
		target_17.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="parent"
		and target_17.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("cmark_node *")
		and target_17.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_17.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_17.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_17.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("cmark_node *")
		and target_17.getThen().(BlockStmt).getStmt(0) instanceof IfStmt
		and target_17.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_48
		and target_17.getEnclosingFunction() = func)
}

/*predicate func_18(Function func) {
	exists(EqualityOperation target_18 |
		target_18.getAnOperand().(PointerFieldAccess).getTarget().getName()="parent"
		and target_18.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("cmark_node *")
		and target_18.getAnOperand().(Literal).getValue()="0"
		and target_18.getEnclosingFunction() = func)
}

*/
/*predicate func_19(Function func) {
	exists(EqualityOperation target_19 |
		target_19.getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_19.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_19.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("cmark_node *")
		and target_19.getEnclosingFunction() = func)
}

*/
predicate func_20(Parameter vnode_170, EqualityOperation target_20) {
		target_20.getAnOperand().(PointerFieldAccess).getTarget().getName()="prev"
		and target_20.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_170
		and target_20.getAnOperand().(Literal).getValue()="0"
}

predicate func_21(Variable vlist_delim_174, Parameter vnode_170, EqualityOperation target_43, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlist_delim_174
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cmark_node_get_list_delim")
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="parent"
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_170
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_43
}

predicate func_22(Variable vlist_number_173, Variable vlist_delim_174, Variable vlistmarker_182, EqualityOperation target_43, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_22.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlistmarker_182
		and target_22.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="20"
		and target_22.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%d%s%s"
		and target_22.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vlist_number_173
		and target_22.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlist_delim_174
		and target_22.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(StringLiteral).getValue()=")"
		and target_22.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getElse().(StringLiteral).getValue()="."
		and target_22.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlist_number_173
		and target_22.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10"
		and target_22.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="  "
		and target_22.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()=" "
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_43
}

predicate func_23(Variable vlistmarker_182, Variable vmarker_width_185, EqualityOperation target_43, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmarker_width_185
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strlen")
		and target_23.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlistmarker_182
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_43
}

/*predicate func_24(Parameter vnode_170, PointerFieldAccess target_24) {
		target_24.getTarget().getName()="parent"
		and target_24.getQualifier().(VariableAccess).getTarget()=vnode_170
		and target_24.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cmark_node_get_list_start")
}

*/
predicate func_25(Variable ventering_178, Parameter vrenderer_170, Parameter vnode_170, PointerFieldAccess target_48, IfStmt target_25) {
		target_25.getCondition().(VariableAccess).getTarget()=ventering_178
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="out"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrenderer_170
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vrenderer_170
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vnode_170
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(StringLiteral).getValue()="**"
		and target_25.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(3).(Literal).getValue()="0"
		and target_25.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="out"
		and target_25.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrenderer_170
		and target_25.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vrenderer_170
		and target_25.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vnode_170
		and target_25.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2).(StringLiteral).getValue()="**"
		and target_25.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(3).(Literal).getValue()="0"
		and target_25.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_48
}

predicate func_26(Parameter vnode_170, VariableAccess target_26) {
		target_26.getTarget()=vnode_170
		and target_26.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_27(Variable vlist_number_173, Parameter vnode_170, VariableAccess target_27) {
		target_27.getTarget()=vlist_number_173
		and target_27.getParent().(AssignExpr).getLValue() = target_27
		and target_27.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cmark_node_get_list_start")
		and target_27.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="parent"
		and target_27.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_170
}

predicate func_28(Variable ventering_178, VariableAccess target_28) {
		target_28.getTarget()=ventering_178
}

predicate func_29(Variable vtmp_172, Parameter vnode_170, VariableAccess target_29) {
		target_29.getTarget()=vnode_170
		and target_29.getParent().(AssignExpr).getRValue() = target_29
		and target_29.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtmp_172
}

predicate func_30(Function func, DeclStmt target_30) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_30
}

predicate func_31(Variable ventering_178, Parameter vnode_170, BlockStmt target_49, NotExpr target_31) {
		target_31.getOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_31.getOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_170
		and target_31.getOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_31.getOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_31.getOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=ventering_178
		and target_31.getParent().(IfStmt).getThen()=target_49
}

predicate func_32(Variable vtmp_172, Parameter vnode_170, AssignExpr target_32) {
		target_32.getLValue().(VariableAccess).getTarget()=vtmp_172
		and target_32.getRValue().(FunctionCall).getTarget().hasName("get_containing_block")
		and target_32.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vnode_170
}

predicate func_33(Variable vtmp_172, LogicalAndExpr target_33) {
		target_33.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_33.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_172
		and target_33.getAnOperand().(FunctionCall).getTarget().hasName("cmark_node_get_list_tight")
		and target_33.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="parent"
		and target_33.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_172
}

predicate func_34(Variable vtmp_172, LogicalAndExpr target_34) {
		target_34.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vtmp_172
		and target_34.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="parent"
		and target_34.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_172
		and target_34.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_34.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_34.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_172
		and target_34.getAnOperand().(FunctionCall).getTarget().hasName("cmark_node_get_list_tight")
		and target_34.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="parent"
		and target_34.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_34.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_172
}

predicate func_35(Variable vtmp_172, Parameter vnode_170, EqualityOperation target_43, ExprStmt target_35) {
		target_35.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtmp_172
		and target_35.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnode_170
		and target_35.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_43
}

predicate func_36(Variable vtmp_172, Variable vlist_number_173, EqualityOperation target_43, WhileStmt target_36) {
		target_36.getCondition().(PointerFieldAccess).getTarget().getName()="prev"
		and target_36.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_172
		and target_36.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtmp_172
		and target_36.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="prev"
		and target_36.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_172
		and target_36.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlist_number_173
		and target_36.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue() instanceof Literal
		and target_36.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_43
}

/*predicate func_37(Variable vtmp_172, AssignExpr target_37) {
		target_37.getLValue().(VariableAccess).getTarget()=vtmp_172
		and target_37.getRValue().(PointerFieldAccess).getTarget().getName()="prev"
		and target_37.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_172
}

*/
predicate func_38(Variable vlist_number_173, ExprStmt target_38) {
		target_38.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlist_number_173
		and target_38.getExpr().(AssignAddExpr).getRValue() instanceof Literal
}

predicate func_39(Variable vtmp_172, Parameter vrenderer_170, ExprStmt target_39) {
		target_39.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="in_tight_list_item"
		and target_39.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrenderer_170
		and target_39.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vtmp_172
		and target_39.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof LogicalAndExpr
		and target_39.getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof LogicalAndExpr
}

predicate func_40(Variable vtmp_172, PointerFieldAccess target_40) {
		target_40.getTarget().getName()="parent"
		and target_40.getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_40.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtmp_172
}

predicate func_42(Parameter vrenderer_170, Parameter vnode_170, ExprStmt target_42) {
		target_42.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="commonmark_render_func"
		and target_42.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="extension"
		and target_42.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_170
		and target_42.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="extension"
		and target_42.getExpr().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_170
		and target_42.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vrenderer_170
		and target_42.getExpr().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vnode_170
}

predicate func_43(Parameter vnode_170, EqualityOperation target_43) {
		target_43.getAnOperand().(FunctionCall).getTarget().hasName("cmark_node_get_list_type")
		and target_43.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="parent"
		and target_43.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_170
}

predicate func_44(Parameter vrenderer_170, LogicalAndExpr target_44) {
		target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrenderer_170
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_44.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getValue()="16"
		and target_44.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(BinaryBitwiseOperation).getValue()="4"
}

predicate func_45(Parameter vnode_170, EqualityOperation target_45) {
		target_45.getAnOperand().(FunctionCall).getTarget().hasName("cmark_node_get_list_type")
		and target_45.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="parent"
		and target_45.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_170
}

predicate func_46(Parameter vrenderer_170, Parameter vnode_170, ExprStmt target_46) {
		target_46.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="out"
		and target_46.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrenderer_170
		and target_46.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vrenderer_170
		and target_46.getExpr().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vnode_170
		and target_46.getExpr().(VariableCall).getArgument(2).(StringLiteral).getValue()="  - "
		and target_46.getExpr().(VariableCall).getArgument(3).(Literal).getValue()="0"
}

predicate func_47(Parameter vrenderer_170, ExprStmt target_47) {
		target_47.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="blankline"
		and target_47.getExpr().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrenderer_170
		and target_47.getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vrenderer_170
}

predicate func_48(Parameter vnode_170, PointerFieldAccess target_48) {
		target_48.getTarget().getName()="type"
		and target_48.getQualifier().(VariableAccess).getTarget()=vnode_170
}

predicate func_49(Variable vtmp_172, Parameter vrenderer_170, BlockStmt target_49) {
		target_49.getStmt(0).(ExprStmt).getExpr() instanceof AssignExpr
		and target_49.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="in_tight_list_item"
		and target_49.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrenderer_170
		and target_49.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vtmp_172
		and target_49.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof LogicalAndExpr
		and target_49.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof LogicalAndExpr
}

from Function func, Variable vtmp_172, Variable vlist_number_173, Variable vlist_delim_174, Variable ventering_178, Variable vlistmarker_182, Variable vmarker_width_185, Parameter vrenderer_170, Parameter vnode_170, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, PointerFieldAccess target_5, PointerFieldAccess target_6, VariableAccess target_7, VariableAccess target_8, Literal target_9, EqualityOperation target_20, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, IfStmt target_25, VariableAccess target_26, VariableAccess target_27, VariableAccess target_28, VariableAccess target_29, DeclStmt target_30, NotExpr target_31, AssignExpr target_32, LogicalAndExpr target_33, LogicalAndExpr target_34, ExprStmt target_35, WhileStmt target_36, ExprStmt target_38, ExprStmt target_39, PointerFieldAccess target_40, ExprStmt target_42, EqualityOperation target_43, LogicalAndExpr target_44, EqualityOperation target_45, ExprStmt target_46, ExprStmt target_47, PointerFieldAccess target_48, BlockStmt target_49
where
func_1(vtmp_172, target_39, target_1)
and func_2(vtmp_172, target_2)
and func_3(vtmp_172, target_40, target_3)
and func_4(vtmp_172, target_39, target_4)
and func_5(vtmp_172, target_35, target_5)
and func_6(vtmp_172, target_6)
and func_7(vtmp_172, target_39, target_7)
and func_8(vtmp_172, target_39, target_8)
and func_9(func, target_9)
and not func_10(vrenderer_170, vnode_170, target_31, target_42, target_43, target_21)
and not func_12(vrenderer_170, vnode_170, target_43, target_44, target_39)
and not func_15(vrenderer_170, target_46)
and not func_16(vlist_number_173, vrenderer_170, target_38, target_47)
and not func_17(target_48, func)
and func_20(vnode_170, target_20)
and func_21(vlist_delim_174, vnode_170, target_43, target_21)
and func_22(vlist_number_173, vlist_delim_174, vlistmarker_182, target_43, target_22)
and func_23(vlistmarker_182, vmarker_width_185, target_43, target_23)
and func_25(ventering_178, vrenderer_170, vnode_170, target_48, target_25)
and func_26(vnode_170, target_26)
and func_27(vlist_number_173, vnode_170, target_27)
and func_28(ventering_178, target_28)
and func_29(vtmp_172, vnode_170, target_29)
and func_30(func, target_30)
and func_31(ventering_178, vnode_170, target_49, target_31)
and func_32(vtmp_172, vnode_170, target_32)
and func_33(vtmp_172, target_33)
and func_34(vtmp_172, target_34)
and func_35(vtmp_172, vnode_170, target_43, target_35)
and func_36(vtmp_172, vlist_number_173, target_43, target_36)
and func_38(vlist_number_173, target_38)
and func_39(vtmp_172, vrenderer_170, target_39)
and func_40(vtmp_172, target_40)
and func_42(vrenderer_170, vnode_170, target_42)
and func_43(vnode_170, target_43)
and func_44(vrenderer_170, target_44)
and func_45(vnode_170, target_45)
and func_46(vrenderer_170, vnode_170, target_46)
and func_47(vrenderer_170, target_47)
and func_48(vnode_170, target_48)
and func_49(vtmp_172, vrenderer_170, target_49)
and vtmp_172.getType().hasName("cmark_node *")
and vlist_number_173.getType().hasName("int")
and vlist_delim_174.getType().hasName("cmark_delim_type")
and ventering_178.getType().hasName("bool")
and vlistmarker_182.getType().hasName("char[20]")
and vmarker_width_185.getType().hasName("bufsize_t")
and vrenderer_170.getType().hasName("cmark_renderer *")
and vnode_170.getType().hasName("cmark_node *")
and vtmp_172.getParentScope+() = func
and vlist_number_173.getParentScope+() = func
and vlist_delim_174.getParentScope+() = func
and ventering_178.getParentScope+() = func
and vlistmarker_182.getParentScope+() = func
and vmarker_width_185.getParentScope+() = func
and vrenderer_170.getParentScope+() = func
and vnode_170.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
