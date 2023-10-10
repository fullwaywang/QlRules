/**
 * @name tidy-html5-efa61528aa500a1efbd2768121820742d3bb709b-CleanNode
 * @id cpp/tidy-html5/efa61528aa500a1efbd2768121820742d3bb709b/CleanNode
 * @description tidy-html5-efa61528aa500a1efbd2768121820742d3bb709b-src/gdoc.c-CleanNode CVE-2021-33391
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vnode_97, BlockStmt target_16, VariableAccess target_0) {
		target_0.getTarget()=vnode_97
		and target_0.getParent().(PointerFieldAccess).getParent().(IfStmt).getThen()=target_16
}

predicate func_1(Parameter vnode_97, IfStmt target_18, VariableAccess target_1) {
		target_1.getTarget()=vnode_97
		and target_18.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLocation())
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="0"
		and not target_2.getValue()="16"
		and target_2.getParent().(NEExpr).getParent().(ForStmt).getCondition() instanceof EqualityOperation
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Parameter vdoc_97, Variable vchild_99, FunctionCall target_3) {
		target_3.getTarget().hasName("CleanNode")
		and not target_3.getTarget().hasName("prvTidypush")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vdoc_97
		and target_3.getArgument(1).(VariableAccess).getTarget()=vchild_99
}

predicate func_4(Variable vchild_99, Variable vnext_99, PointerFieldAccess target_19, ExprStmt target_10, AssignExpr target_21) {
	exists(WhileStmt target_4 |
		target_4.getCondition().(VariableAccess).getTarget()=vchild_99
		and target_4.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_4.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("prvTidynodeIsElement")
		and target_4.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchild_99
		and target_4.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchild_99
		and target_4.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getType().hasName("Node *")
		and target_4.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vnext_99
		and target_4.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("prvTidypop")
		and target_4.getStmt().(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_4.getCondition().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_21.getRValue().(VariableAccess).getLocation().isBefore(target_4.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getLocation()))
}

/*predicate func_6(LogicalAndExpr target_22, Function func) {
	exists(ContinueStmt target_6 |
		target_6.toString() = "continue;"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(3)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
		and target_6.getEnclosingFunction() = func)
}

*/
/*predicate func_7(Variable vchild_99, Variable vnext_99, AssignExpr target_21, ExprStmt target_10) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchild_99
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getType().hasName("Node *")
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vnext_99
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("prvTidypop")
		and target_7.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Stack *")
		and target_21.getLValue().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_8(Function func) {
	exists(LabelStmt target_8 |
		target_8.toString() = "label ...:"
		and target_8.getEnclosingFunction() = func)
}

*/
predicate func_9(PointerFieldAccess target_19, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("prvTidyfreeStack")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("Stack *")
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Variable vchild_99, Variable vnext_99, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnext_99
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchild_99
}

predicate func_11(Parameter vnode_97, Variable vchild_99, AssignExpr target_11) {
		target_11.getLValue().(VariableAccess).getTarget()=vchild_99
		and target_11.getRValue().(PointerFieldAccess).getTarget().getName()="content"
		and target_11.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_97
}

predicate func_12(Parameter vdoc_97, VariableAccess target_12) {
		target_12.getTarget()=vdoc_97
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_13(Variable vchild_99, BlockStmt target_23, VariableAccess target_13) {
		target_13.getTarget()=vchild_99
		and target_13.getParent().(NEExpr).getAnOperand() instanceof Literal
		and target_13.getParent().(NEExpr).getParent().(ForStmt).getStmt()=target_23
}

predicate func_14(Variable vchild_99, Variable vnext_99, VariableAccess target_14) {
		target_14.getTarget()=vnext_99
		and target_14.getParent().(AssignExpr).getRValue() = target_14
		and target_14.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchild_99
}

predicate func_15(Variable vchild_99, Variable vnext_99, PointerFieldAccess target_19, ForStmt target_15) {
		target_15.getInitialization().(ExprStmt).getExpr() instanceof AssignExpr
		and target_15.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vchild_99
		and target_15.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_15.getUpdate().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchild_99
		and target_15.getUpdate().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnext_99
		and target_15.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("prvTidynodeIsElement")
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchild_99
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("prvTidyDiscardElement")
		and target_15.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("prvTidyDiscardElement")
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
}

predicate func_16(BlockStmt target_16) {
		target_16.getStmt(0) instanceof ForStmt
}

predicate func_18(Parameter vnode_97, IfStmt target_18) {
		target_18.getCondition().(PointerFieldAccess).getTarget().getName()="content"
		and target_18.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_97
		and target_18.getThen().(BlockStmt).getStmt(0) instanceof ForStmt
}

predicate func_19(Parameter vnode_97, PointerFieldAccess target_19) {
		target_19.getTarget().getName()="content"
		and target_19.getQualifier().(VariableAccess).getTarget()=vnode_97
}

predicate func_21(Variable vchild_99, Variable vnext_99, AssignExpr target_21) {
		target_21.getLValue().(VariableAccess).getTarget()=vchild_99
		and target_21.getRValue().(VariableAccess).getTarget()=vnext_99
}

predicate func_22(Variable vchild_99, LogicalAndExpr target_22) {
		target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vchild_99
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="tag"
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchild_99
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="id"
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tag"
		and target_22.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchild_99
		and target_22.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_22.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vchild_99
}

predicate func_23(Parameter vdoc_97, Variable vchild_99, BlockStmt target_23) {
		target_23.getStmt(0) instanceof ExprStmt
		and target_23.getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("prvTidynodeIsElement")
		and target_23.getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchild_99
		and target_23.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vchild_99
		and target_23.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="tag"
		and target_23.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="id"
		and target_23.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("prvTidyDiscardElement")
		and target_23.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdoc_97
		and target_23.getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vchild_99
}

from Function func, Parameter vdoc_97, Parameter vnode_97, Variable vchild_99, Variable vnext_99, VariableAccess target_0, VariableAccess target_1, Literal target_2, FunctionCall target_3, ExprStmt target_10, AssignExpr target_11, VariableAccess target_12, VariableAccess target_13, VariableAccess target_14, ForStmt target_15, BlockStmt target_16, IfStmt target_18, PointerFieldAccess target_19, AssignExpr target_21, LogicalAndExpr target_22, BlockStmt target_23
where
func_0(vnode_97, target_16, target_0)
and func_1(vnode_97, target_18, target_1)
and func_2(func, target_2)
and func_3(vdoc_97, vchild_99, target_3)
and not func_4(vchild_99, vnext_99, target_19, target_10, target_21)
and not func_9(target_19, func)
and func_10(vchild_99, vnext_99, target_10)
and func_11(vnode_97, vchild_99, target_11)
and func_12(vdoc_97, target_12)
and func_13(vchild_99, target_23, target_13)
and func_14(vchild_99, vnext_99, target_14)
and func_15(vchild_99, vnext_99, target_19, target_15)
and func_16(target_16)
and func_18(vnode_97, target_18)
and func_19(vnode_97, target_19)
and func_21(vchild_99, vnext_99, target_21)
and func_22(vchild_99, target_22)
and func_23(vdoc_97, vchild_99, target_23)
and vdoc_97.getType().hasName("TidyDocImpl *")
and vnode_97.getType().hasName("Node *")
and vchild_99.getType().hasName("Node *")
and vnext_99.getType().hasName("Node *")
and vdoc_97.getParentScope+() = func
and vnode_97.getParentScope+() = func
and vchild_99.getParentScope+() = func
and vnext_99.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
