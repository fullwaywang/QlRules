/**
 * @name libxslt-50f9c9cd3-xsltApplyTemplates
 * @id cpp/libxslt/50f9c9cd3/xsltApplyTemplates
 * @description libxslt-50f9c9cd3-libxslt/transform.c-xsltApplyTemplates CVE-2021-30560
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdelNode_4867, BlockStmt target_60, ExprStmt target_53, ExprStmt target_56, VariableAccess target_0) {
		target_0.getTarget()=vdelNode_4867
		and target_0.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_60
		and target_53.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_56.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_2(Variable vcur_4867, BlockStmt target_61, PointerFieldAccess target_63) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_2.getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_61
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_63.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_3(Variable vcur_4867, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="type"
		and target_3.getQualifier().(VariableAccess).getTarget()=vcur_4867
}

*/
predicate func_4(Parameter vctxt_4857, ExprStmt target_64, LogicalAndExpr target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="traceCode"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4857
		and target_4.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="traceCode"
		and target_4.getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4857
		and target_4.getParent().(IfStmt).getThen()=target_64
}

predicate func_5(Variable vcur_4867, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="type"
		and target_5.getQualifier().(VariableAccess).getTarget()=vcur_4867
}

predicate func_6(Variable vcur_4867, EqualityOperation target_6) {
		target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
}

predicate func_7(Variable vcur_4867, Variable vlist_4868, PointerFieldAccess target_5, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("xmlXPathNodeSetAddUnique")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlist_4868
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcur_4867
		and target_7.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
}

predicate func_8(Variable vcur_4867, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="type"
		and target_8.getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_8.getParent().(VariableCall).getParent().(ExprStmt).getExpr() instanceof VariableCall
}

predicate func_9(Variable vcur_4867, VariableAccess target_9) {
		target_9.getTarget()=vcur_4867
}

predicate func_10(Variable vcur_4867, VariableAccess target_10) {
		target_10.getTarget()=vcur_4867
}

predicate func_11(Variable vcur_4867, VariableAccess target_11) {
		target_11.getTarget()=vcur_4867
}

predicate func_13(Variable vcur_4867, VariableAccess target_13) {
		target_13.getTarget()=vcur_4867
}

predicate func_14(Variable vcur_4867, VariableAccess target_14) {
		target_14.getTarget()=vcur_4867
}

predicate func_20(Function func, LabelStmt target_20) {
		target_20.toString() = "label ...:"
		and target_20.getEnclosingFunction() = func
}

predicate func_22(Variable vcur_4867, Variable vdelNode_4867, Variable vxsltGenericDebug, Variable vxsltGenericDebugContext, SwitchStmt target_22) {
		target_22.getExpr().(PointerFieldAccess).getTarget().getName()="type"
		and target_22.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_22.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr() instanceof EnumConstantAccess
		and target_22.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_22.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_22.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="stripSpaces"
		and target_22.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="style"
		and target_22.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_22.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ns"
		and target_22.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_22.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("xmlStrEqual")
		and target_22.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_22.getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr() instanceof EnumConstantAccess
		and target_22.getStmt().(BlockStmt).getStmt(4).(SwitchCase).getExpr() instanceof EnumConstantAccess
		and target_22.getStmt().(BlockStmt).getStmt(5).(SwitchCase).getExpr() instanceof EnumConstantAccess
		and target_22.getStmt().(BlockStmt).getStmt(6).(SwitchCase).getExpr() instanceof EnumConstantAccess
		and target_22.getStmt().(BlockStmt).getStmt(7).(SwitchCase).getExpr() instanceof EnumConstantAccess
		and target_22.getStmt().(BlockStmt).getStmt(8) instanceof ExprStmt
		and target_22.getStmt().(BlockStmt).getStmt(9).(BreakStmt).toString() = "break;"
		and target_22.getStmt().(BlockStmt).getStmt(11).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="next"
		and target_22.getStmt().(BlockStmt).getStmt(11).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_22.getStmt().(BlockStmt).getStmt(11).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_22.getStmt().(BlockStmt).getStmt(11).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="prev"
		and target_22.getStmt().(BlockStmt).getStmt(11).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="next"
		and target_22.getStmt().(BlockStmt).getStmt(11).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="prev"
		and target_22.getStmt().(BlockStmt).getStmt(11).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_22.getStmt().(BlockStmt).getStmt(12).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="prev"
		and target_22.getStmt().(BlockStmt).getStmt(12).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_22.getStmt().(BlockStmt).getStmt(12).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_22.getStmt().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_22.getStmt().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="prev"
		and target_22.getStmt().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_22.getStmt().(BlockStmt).getStmt(12).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_22.getStmt().(BlockStmt).getStmt(13).(BreakStmt).toString() = "break;"
		and target_22.getStmt().(BlockStmt).getStmt(15).(BreakStmt).toString() = "break;"
		and target_22.getStmt().(BlockStmt).getStmt(16).(SwitchCase).toString() = "default: "
		and target_22.getStmt().(BlockStmt).getStmt(17).(IfStmt).getCondition() instanceof LogicalAndExpr
		and target_22.getStmt().(BlockStmt).getStmt(17).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxsltGenericDebug
		and target_22.getStmt().(BlockStmt).getStmt(17).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vxsltGenericDebugContext
		and target_22.getStmt().(BlockStmt).getStmt(17).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(StringLiteral).getValue()="xsltApplyTemplates: skipping cur type %d\n"
		and target_22.getStmt().(BlockStmt).getStmt(17).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="type"
		and target_22.getStmt().(BlockStmt).getStmt(17).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_22.getStmt().(BlockStmt).getStmt(18).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdelNode_4867
		and target_22.getStmt().(BlockStmt).getStmt(18).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcur_4867
}

/*predicate func_23(Function func, SwitchCase target_23) {
		target_23.getExpr() instanceof EnumConstantAccess
		and target_23.getEnclosingFunction() = func
}

*/
/*predicate func_24(Variable vcur_4867, Parameter vctxt_4857, BlockStmt target_61, LogicalAndExpr target_24) {
		target_24.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_24.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("xsltIsBlank")
		and target_24.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="content"
		and target_24.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_24.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="parent"
		and target_24.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_24.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_24.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_24.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_24.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_24.getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_24.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="stripSpaces"
		and target_24.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="style"
		and target_24.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4857
		and target_24.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_24.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_61
}

*/
/*predicate func_25(Variable vcur_4867, EqualityOperation target_66, PointerFieldAccess target_25) {
		target_25.getTarget().getName()="parent"
		and target_25.getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_25.getQualifier().(VariableAccess).getLocation().isBefore(target_66.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
/*predicate func_26(Variable vcur_4867, Parameter vctxt_4857, BlockStmt target_61, EqualityOperation target_26) {
		target_26.getAnOperand().(PointerFieldAccess).getTarget().getName()="stripSpaces"
		and target_26.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="style"
		and target_26.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4857
		and target_26.getAnOperand().(Literal).getValue()="0"
		and target_26.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_26.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("xsltIsBlank")
		and target_26.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="content"
		and target_26.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="parent"
		and target_26.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_26.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_26.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_26.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_26.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_26.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_26.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_61
}

*/
predicate func_27(LogicalAndExpr target_67, Function func, DeclStmt target_27) {
		target_27.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_67
		and target_27.getEnclosingFunction() = func
}

/*predicate func_28(Variable vcur_4867, Variable vval_5007, LogicalAndExpr target_67, IfStmt target_28) {
		target_28.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ns"
		and target_28.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_28.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_28.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vval_5007
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlHashLookup2")
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="stripSpaces"
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="style"
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="href"
		and target_28.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ns"
		and target_28.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vval_5007
		and target_28.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_28.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vval_5007
		and target_28.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlHashLookup2")
		and target_28.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vval_5007
		and target_28.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlHashLookup2")
		and target_28.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="stripSpaces"
		and target_28.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="style"
		and target_28.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_28.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_28.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_28.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_67
}

*/
predicate func_29(Variable vcur_4867, Variable vval_5007, Parameter vctxt_4857, EqualityOperation target_66, ExprStmt target_29) {
		target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vval_5007
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlHashLookup2")
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="stripSpaces"
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="style"
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4857
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="href"
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ns"
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_29.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_29.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_66
}

/*predicate func_30(Variable vval_5007, EqualityOperation target_66, IfStmt target_30) {
		target_30.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vval_5007
		and target_30.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vval_5007
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlHashLookup2")
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="stripSpaces"
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="style"
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="*"
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="href"
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ns"
		and target_30.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_66
}

*/
/*predicate func_31(Variable vval_5007, BlockStmt target_68, ExprStmt target_29, VariableAccess target_31) {
		target_31.getTarget()=vval_5007
		and target_31.getParent().(EQExpr).getAnOperand().(Literal).getValue()="0"
		and target_31.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_68
		and target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_31.getLocation())
}

*/
/*predicate func_33(Variable vcur_4867, Variable vval_5007, Parameter vctxt_4857, EqualityOperation target_69, ExprStmt target_33) {
		target_33.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vval_5007
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlHashLookup2")
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="stripSpaces"
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="style"
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4857
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="*"
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="href"
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ns"
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_33.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_33.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_69
}

*/
/*predicate func_34(Variable vcur_4867, Variable vval_5007, Parameter vctxt_4857, EqualityOperation target_66, ExprStmt target_34) {
		target_34.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vval_5007
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlHashLookup2")
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="stripSpaces"
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="style"
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4857
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_34.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_34.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_66
}

*/
/*predicate func_35(Variable vcur_4867, Variable vdelNode_4867, Variable vval_5007, LogicalAndExpr target_67, IfStmt target_35) {
		target_35.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vval_5007
		and target_35.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_35.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("xmlStrEqual")
		and target_35.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vval_5007
		and target_35.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="strip"
		and target_35.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdelNode_4867
		and target_35.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcur_4867
		and target_35.getThen().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_35.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_67
}

*/
/*predicate func_36(Variable vcur_4867, Variable vdelNode_4867, LogicalAndExpr target_70, PointerFieldAccess target_71, ExprStmt target_7, ExprStmt target_36) {
		target_36.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdelNode_4867
		and target_36.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcur_4867
		and target_36.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_70
		and target_71.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_36.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_36.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

*/
/*predicate func_37(LogicalAndExpr target_70, Function func, BreakStmt target_37) {
		target_37.toString() = "break;"
		and target_37.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_70
		and target_37.getEnclosingFunction() = func
}

*/
/*predicate func_39(Function func, SwitchCase target_39) {
		target_39.getExpr() instanceof EnumConstantAccess
		and target_39.getEnclosingFunction() = func
}

*/
/*predicate func_40(Function func, SwitchCase target_40) {
		target_40.getExpr() instanceof EnumConstantAccess
		and target_40.getEnclosingFunction() = func
}

*/
/*predicate func_41(Function func, SwitchCase target_41) {
		target_41.getExpr() instanceof EnumConstantAccess
		and target_41.getEnclosingFunction() = func
}

*/
/*predicate func_42(Function func, SwitchCase target_42) {
		target_42.getExpr() instanceof EnumConstantAccess
		and target_42.getEnclosingFunction() = func
}

*/
/*predicate func_43(Function func, SwitchCase target_43) {
		target_43.getExpr() instanceof EnumConstantAccess
		and target_43.getEnclosingFunction() = func
}

*/
/*predicate func_44(PointerFieldAccess target_5, Function func, BreakStmt target_44) {
		target_44.toString() = "break;"
		and target_44.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_44.getEnclosingFunction() = func
}

*/
/*predicate func_46(Variable vcur_4867, PointerFieldAccess target_5, IfStmt target_46) {
		target_46.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="next"
		and target_46.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_46.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_46.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="prev"
		and target_46.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="next"
		and target_46.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_46.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="prev"
		and target_46.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_46.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
}

*/
/*predicate func_47(Variable vcur_4867, PointerFieldAccess target_5, IfStmt target_47) {
		target_47.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="prev"
		and target_47.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_47.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_47.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_47.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="prev"
		and target_47.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_47.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
		and target_47.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_47.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
}

*/
/*predicate func_48(PointerFieldAccess target_5, Function func, BreakStmt target_48) {
		target_48.toString() = "break;"
		and target_48.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_48.getEnclosingFunction() = func
}

*/
/*predicate func_50(PointerFieldAccess target_5, Function func, BreakStmt target_50) {
		target_50.toString() = "break;"
		and target_50.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_50.getEnclosingFunction() = func
}

*/
/*predicate func_51(Function func, SwitchCase target_51) {
		target_51.toString() = "default: "
		and target_51.getEnclosingFunction() = func
}

*/
/*predicate func_52(Variable vcur_4867, Variable vxsltGenericDebug, Variable vxsltGenericDebugContext, PointerFieldAccess target_5, IfStmt target_52) {
		target_52.getCondition() instanceof LogicalAndExpr
		and target_52.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxsltGenericDebug
		and target_52.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vxsltGenericDebugContext
		and target_52.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(StringLiteral).getValue()="xsltApplyTemplates: skipping cur type %d\n"
		and target_52.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="type"
		and target_52.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_52.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
}

*/
predicate func_53(Variable vcur_4867, Variable vdelNode_4867, ExprStmt target_53) {
		target_53.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdelNode_4867
		and target_53.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcur_4867
}

predicate func_54(Variable vdelNode_4867, Variable vxsltGenericDebug, Variable vxsltGenericDebugContext, Parameter vctxt_4857, IfStmt target_54) {
		target_54.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdelNode_4867
		and target_54.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_54.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="traceCode"
		and target_54.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4857
		and target_54.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="traceCode"
		and target_54.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxsltGenericDebug
		and target_54.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vxsltGenericDebugContext
		and target_54.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(StringLiteral).getValue()="xsltApplyTemplates: removing ignorable blank cur\n"
		and target_54.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlUnlinkNode")
		and target_54.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdelNode_4867
		and target_54.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFreeNode")
		and target_54.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdelNode_4867
		and target_54.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdelNode_4867
		and target_54.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

/*predicate func_55(Variable vxsltGenericDebug, Variable vxsltGenericDebugContext, Parameter vctxt_4857, IfStmt target_55) {
		target_55.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="traceCode"
		and target_55.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4857
		and target_55.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="traceCode"
		and target_55.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4857
		and target_55.getThen().(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxsltGenericDebug
		and target_55.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vxsltGenericDebugContext
		and target_55.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1).(StringLiteral).getValue()="xsltApplyTemplates: removing ignorable blank cur\n"
}

*/
predicate func_56(Variable vdelNode_4867, ExprStmt target_56) {
		target_56.getExpr().(FunctionCall).getTarget().hasName("xmlUnlinkNode")
		and target_56.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdelNode_4867
}

/*predicate func_57(Variable vdelNode_4867, ExprStmt target_57) {
		target_57.getExpr().(FunctionCall).getTarget().hasName("xmlFreeNode")
		and target_57.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdelNode_4867
}

*/
/*predicate func_58(Variable vdelNode_4867, ExprStmt target_58) {
		target_58.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdelNode_4867
		and target_58.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

*/
predicate func_59(Function func, LabelStmt target_59) {
		target_59.toString() = "label ...:"
		and target_59.getName() ="error"
		and target_59.getEnclosingFunction() = func
}

predicate func_60(BlockStmt target_60) {
		target_60.getStmt(0) instanceof IfStmt
		and target_60.getStmt(1) instanceof ExprStmt
		and target_60.getStmt(2) instanceof ExprStmt
		and target_60.getStmt(3) instanceof ExprStmt
}

predicate func_61(BlockStmt target_61) {
		target_61.getStmt(1) instanceof IfStmt
		and target_61.getStmt(2) instanceof IfStmt
}

predicate func_63(Variable vcur_4867, PointerFieldAccess target_63) {
		target_63.getTarget().getName()="ns"
		and target_63.getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_63.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
}

predicate func_64(ExprStmt target_64) {
		target_64.getExpr() instanceof VariableCall
}

predicate func_66(Variable vcur_4867, EqualityOperation target_66) {
		target_66.getAnOperand().(PointerFieldAccess).getTarget().getName()="ns"
		and target_66.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_66.getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
		and target_66.getAnOperand() instanceof Literal
}

predicate func_67(LogicalAndExpr target_67) {
		target_67.getAnOperand() instanceof LogicalAndExpr
		and target_67.getAnOperand() instanceof EqualityOperation
}

predicate func_68(BlockStmt target_68) {
		target_68.getStmt(0) instanceof ExprStmt
}

predicate func_69(Variable vval_5007, EqualityOperation target_69) {
		target_69.getAnOperand().(VariableAccess).getTarget()=vval_5007
		and target_69.getAnOperand() instanceof Literal
}

predicate func_70(LogicalAndExpr target_70) {
		target_70.getAnOperand() instanceof EqualityOperation
		and target_70.getAnOperand() instanceof FunctionCall
}

predicate func_71(Variable vcur_4867, PointerFieldAccess target_71) {
		target_71.getTarget().getName()="name"
		and target_71.getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_71.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcur_4867
}

from Function func, Variable vcur_4867, Variable vdelNode_4867, Variable vlist_4868, Variable vxsltGenericDebug, Variable vxsltGenericDebugContext, Variable vval_5007, Parameter vctxt_4857, VariableAccess target_0, LogicalAndExpr target_4, PointerFieldAccess target_5, EqualityOperation target_6, ExprStmt target_7, PointerFieldAccess target_8, VariableAccess target_9, VariableAccess target_10, VariableAccess target_11, VariableAccess target_13, VariableAccess target_14, LabelStmt target_20, SwitchStmt target_22, DeclStmt target_27, ExprStmt target_29, ExprStmt target_53, IfStmt target_54, ExprStmt target_56, LabelStmt target_59, BlockStmt target_60, BlockStmt target_61, PointerFieldAccess target_63, ExprStmt target_64, EqualityOperation target_66, LogicalAndExpr target_67, BlockStmt target_68, EqualityOperation target_69, LogicalAndExpr target_70, PointerFieldAccess target_71
where
func_0(vdelNode_4867, target_60, target_53, target_56, target_0)
and not func_2(vcur_4867, target_61, target_63)
and func_4(vctxt_4857, target_64, target_4)
and func_5(vcur_4867, target_5)
and func_6(vcur_4867, target_6)
and func_7(vcur_4867, vlist_4868, target_5, target_7)
and func_8(vcur_4867, target_8)
and func_9(vcur_4867, target_9)
and func_10(vcur_4867, target_10)
and func_11(vcur_4867, target_11)
and func_13(vcur_4867, target_13)
and func_14(vcur_4867, target_14)
and func_20(func, target_20)
and func_22(vcur_4867, vdelNode_4867, vxsltGenericDebug, vxsltGenericDebugContext, target_22)
and func_27(target_67, func, target_27)
and func_29(vcur_4867, vval_5007, vctxt_4857, target_66, target_29)
and func_53(vcur_4867, vdelNode_4867, target_53)
and func_54(vdelNode_4867, vxsltGenericDebug, vxsltGenericDebugContext, vctxt_4857, target_54)
and func_56(vdelNode_4867, target_56)
and func_59(func, target_59)
and func_60(target_60)
and func_61(target_61)
and func_63(vcur_4867, target_63)
and func_64(target_64)
and func_66(vcur_4867, target_66)
and func_67(target_67)
and func_68(target_68)
and func_69(vval_5007, target_69)
and func_70(target_70)
and func_71(vcur_4867, target_71)
and vcur_4867.getType().hasName("xmlNodePtr")
and vdelNode_4867.getType().hasName("xmlNodePtr")
and vlist_4868.getType().hasName("xmlNodeSetPtr")
and vxsltGenericDebug.getType().hasName("xmlGenericErrorFunc")
and vxsltGenericDebugContext.getType().hasName("void *")
and vval_5007.getType().hasName("const xmlChar *")
and vctxt_4857.getType().hasName("xsltTransformContextPtr")
and vcur_4867.getParentScope+() = func
and vdelNode_4867.getParentScope+() = func
and vlist_4868.getParentScope+() = func
and not vxsltGenericDebug.getParentScope+() = func
and not vxsltGenericDebugContext.getParentScope+() = func
and vval_5007.getParentScope+() = func
and vctxt_4857.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
