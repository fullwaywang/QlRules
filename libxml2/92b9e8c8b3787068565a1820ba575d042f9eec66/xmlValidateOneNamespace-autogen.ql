/**
 * @name libxml2-92b9e8c8b3787068565a1820ba575d042f9eec66-xmlValidateOneNamespace
 * @id cpp/libxml2/92b9e8c8b3787068565a1820ba575d042f9eec66/xmlValidateOneNamespace
 * @description libxml2-92b9e8c8b3787068565a1820ba575d042f9eec66-valid.c-xmlValidateOneNamespace CVE-2017-0663
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vattrDecl_4536, BlockStmt target_6, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="atype"
		and target_0.getQualifier().(VariableAccess).getTarget()=vattrDecl_4536
		and target_0.getParent().(EQExpr).getAnOperand() instanceof EnumConstantAccess
		and target_0.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_6
}

predicate func_1(Variable vattrDecl_4536, BlockStmt target_7, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="atype"
		and target_1.getQualifier().(VariableAccess).getTarget()=vattrDecl_4536
		and target_1.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_2(Parameter vns_4534, Parameter vvalue_4534, Variable vattrDecl_4536, Variable vret_4538, Parameter vctxt_4533, Parameter vdoc_4533, Function func, IfStmt target_2) {
		target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="atype"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattrDecl_4536
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("xmlAddID")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_4533
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdoc_4533
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvalue_4534
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vns_4534
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_4538
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

/*predicate func_3(Parameter vns_4534, Parameter vvalue_4534, Variable vret_4538, Parameter vctxt_4533, Parameter vdoc_4533, EqualityOperation target_8, IfStmt target_3) {
		target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("xmlAddID")
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_4533
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdoc_4533
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvalue_4534
		and target_3.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vns_4534
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_4538
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
}

*/
predicate func_4(Parameter vns_4534, Parameter vvalue_4534, Variable vattrDecl_4536, Variable vret_4538, Parameter vctxt_4533, Parameter vdoc_4533, Function func, IfStmt target_4) {
		target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="atype"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattrDecl_4536
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="atype"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattrDecl_4536
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("xmlAddRef")
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_4533
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdoc_4533
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvalue_4534
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vns_4534
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_4538
		and target_4.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

/*predicate func_5(Parameter vns_4534, Parameter vvalue_4534, Variable vret_4538, Parameter vctxt_4533, Parameter vdoc_4533, LogicalOrExpr target_9, IfStmt target_5) {
		target_5.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("xmlAddRef")
		and target_5.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_4533
		and target_5.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdoc_4533
		and target_5.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vvalue_4534
		and target_5.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vns_4534
		and target_5.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_4538
		and target_5.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
}

*/
predicate func_6(BlockStmt target_6) {
		target_6.getStmt(0) instanceof IfStmt
}

predicate func_7(Parameter vvalue_4534, Parameter vdoc_4533, BlockStmt target_7) {
		target_7.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("xmlNotationPtr")
		and target_7.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlGetDtdNotationDesc")
		and target_7.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="intSubset"
		and target_7.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdoc_4533
		and target_7.getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvalue_4534
}

predicate func_8(Variable vattrDecl_4536, EqualityOperation target_8) {
		target_8.getAnOperand().(PointerFieldAccess).getTarget().getName()="atype"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattrDecl_4536
		and target_8.getAnOperand() instanceof EnumConstantAccess
}

predicate func_9(LogicalOrExpr target_9) {
		target_9.getAnOperand() instanceof EqualityOperation
		and target_9.getAnOperand() instanceof EqualityOperation
}

from Function func, Parameter vns_4534, Parameter vvalue_4534, Variable vattrDecl_4536, Variable vret_4538, Parameter vctxt_4533, Parameter vdoc_4533, PointerFieldAccess target_0, PointerFieldAccess target_1, IfStmt target_2, IfStmt target_4, BlockStmt target_6, BlockStmt target_7, EqualityOperation target_8, LogicalOrExpr target_9
where
func_0(vattrDecl_4536, target_6, target_0)
and func_1(vattrDecl_4536, target_7, target_1)
and func_2(vns_4534, vvalue_4534, vattrDecl_4536, vret_4538, vctxt_4533, vdoc_4533, func, target_2)
and func_4(vns_4534, vvalue_4534, vattrDecl_4536, vret_4538, vctxt_4533, vdoc_4533, func, target_4)
and func_6(target_6)
and func_7(vvalue_4534, vdoc_4533, target_7)
and func_8(vattrDecl_4536, target_8)
and func_9(target_9)
and vns_4534.getType().hasName("xmlNsPtr")
and vvalue_4534.getType().hasName("const xmlChar *")
and vattrDecl_4536.getType().hasName("xmlAttributePtr")
and vret_4538.getType().hasName("int")
and vctxt_4533.getType().hasName("xmlValidCtxtPtr")
and vdoc_4533.getType().hasName("xmlDocPtr")
and vns_4534.getFunction() = func
and vvalue_4534.getFunction() = func
and vattrDecl_4536.(LocalVariable).getFunction() = func
and vret_4538.(LocalVariable).getFunction() = func
and vctxt_4533.getFunction() = func
and vdoc_4533.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
