/**
 * @name libxml2-4472c3a5a5b516aaf59b89be602fbce52756c3e9-xmlStrPrintf
 * @id cpp/libxml2/4472c3a5a5b516aaf59b89be602fbce52756c3e9/xmlStrPrintf
 * @description libxml2-4472c3a5a5b516aaf59b89be602fbce52756c3e9-xmlstring.c-xmlStrPrintf CVE-2016-4448
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, DeclStmt target_0) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

predicate func_1(Function func, DeclStmt target_1) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vmsg_548, Parameter vbuf_548, Function func, IfStmt target_2) {
		target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuf_548
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vmsg_548
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

/*predicate func_3(LogicalOrExpr target_9, Function func, ReturnStmt target_3) {
		target_3.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_9
		and target_3.getEnclosingFunction() = func
}

*/
predicate func_4(Parameter vmsg_548, Variable vargs_549, Function func, ExprStmt target_4) {
		target_4.getExpr().(BuiltInVarArgsStart).getVAList().(VariableAccess).getTarget()=vargs_549
		and target_4.getExpr().(BuiltInVarArgsStart).getLastNamedParameter().(VariableAccess).getTarget()=vmsg_548
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vmsg_548, Variable vargs_549, Variable vret_550, Parameter vbuf_548, Parameter vlen_548, Function func, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_550
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vsnprintf")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_548
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_548
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vmsg_548
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vargs_549
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Variable vargs_549, Function func, ExprStmt target_6) {
		target_6.getExpr().(BuiltInVarArgsEnd).getVAList().(VariableAccess).getTarget()=vargs_549
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Parameter vbuf_548, Parameter vlen_548, Function func, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuf_548
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_548
		and target_7.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vret_550, Function func, ReturnStmt target_8) {
		target_8.getExpr().(VariableAccess).getTarget()=vret_550
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(LogicalOrExpr target_9) {
		target_9.getAnOperand() instanceof EqualityOperation
		and target_9.getAnOperand() instanceof EqualityOperation
}

from Function func, Parameter vmsg_548, Variable vargs_549, Variable vret_550, Parameter vbuf_548, Parameter vlen_548, DeclStmt target_0, DeclStmt target_1, IfStmt target_2, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ReturnStmt target_8, LogicalOrExpr target_9
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(vmsg_548, vbuf_548, func, target_2)
and func_4(vmsg_548, vargs_549, func, target_4)
and func_5(vmsg_548, vargs_549, vret_550, vbuf_548, vlen_548, func, target_5)
and func_6(vargs_549, func, target_6)
and func_7(vbuf_548, vlen_548, func, target_7)
and func_8(vret_550, func, target_8)
and func_9(target_9)
and vmsg_548.getType().hasName("const xmlChar *")
and vargs_549.getType().hasName("va_list")
and vret_550.getType().hasName("int")
and vbuf_548.getType().hasName("xmlChar *")
and vlen_548.getType().hasName("int")
and vmsg_548.getFunction() = func
and vargs_549.(LocalVariable).getFunction() = func
and vret_550.(LocalVariable).getFunction() = func
and vbuf_548.getFunction() = func
and vlen_548.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
