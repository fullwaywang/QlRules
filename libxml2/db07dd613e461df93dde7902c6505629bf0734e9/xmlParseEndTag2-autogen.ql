/**
 * @name libxml2-db07dd613e461df93dde7902c6505629bf0734e9-xmlParseEndTag2
 * @id cpp/libxml2/db07dd613e461df93dde7902c6505629bf0734e9/xmlParseEndTag2
 * @description libxml2-db07dd613e461df93dde7902c6505629bf0734e9-parser.c-xmlParseEndTag2 CVE-2016-1838
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_9825, ExprStmt target_5, PointerFieldAccess target_6, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("size_t")
		and target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="end"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9825
		and target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getTarget().getName()="cur"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getRightOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9825
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_9825, Parameter vtlen_9826, BlockStmt target_7, LogicalAndExpr target_8) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof RelationalOperation
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vtlen_9826
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("xmlStrncmp")
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cur"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9825
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9825
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtlen_9826
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_7
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(Parameter vtlen_9826, BlockStmt target_9, LogicalAndExpr target_8, EqualityOperation target_4) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtlen_9826
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getAnOperand() instanceof EqualityOperation
		and target_2.getParent().(IfStmt).getThen()=target_9
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vctxt_9825, Parameter vtlen_9826, BlockStmt target_7, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vtlen_9826
		and target_3.getLesserOperand().(Literal).getValue()="0"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("xmlStrncmp")
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cur"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9825
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9825
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtlen_9826
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_4(Parameter vctxt_9825, Parameter vtlen_9826, BlockStmt target_9, EqualityOperation target_4) {
		target_4.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cur"
		and target_4.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_4.getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9825
		and target_4.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vtlen_9826
		and target_4.getAnOperand().(CharLiteral).getValue()="62"
		and target_4.getParent().(IfStmt).getThen()=target_9
}

predicate func_5(Parameter vctxt_9825, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("xmlPopInput")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_9825
}

predicate func_6(Parameter vctxt_9825, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="cur"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9825
}

predicate func_7(Parameter vtlen_9826, BlockStmt target_7) {
		target_7.getStmt(0).(IfStmt).getCondition() instanceof EqualityOperation
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cur"
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtlen_9826
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="col"
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtlen_9826
		and target_7.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_8(Parameter vctxt_9825, Parameter vtlen_9826, LogicalAndExpr target_8) {
		target_8.getAnOperand() instanceof RelationalOperation
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("xmlStrncmp")
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cur"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9825
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9825
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtlen_9826
		and target_8.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_9(Parameter vctxt_9825, Parameter vtlen_9826, BlockStmt target_9) {
		target_9.getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="cur"
		and target_9.getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_9.getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_9825
		and target_9.getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vtlen_9826
		and target_9.getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

from Function func, Parameter vctxt_9825, Parameter vtlen_9826, RelationalOperation target_3, EqualityOperation target_4, ExprStmt target_5, PointerFieldAccess target_6, BlockStmt target_7, LogicalAndExpr target_8, BlockStmt target_9
where
not func_0(vctxt_9825, target_5, target_6, func)
and not func_1(vctxt_9825, vtlen_9826, target_7, target_8)
and not func_2(vtlen_9826, target_9, target_8, target_4)
and func_3(vctxt_9825, vtlen_9826, target_7, target_3)
and func_4(vctxt_9825, vtlen_9826, target_9, target_4)
and func_5(vctxt_9825, target_5)
and func_6(vctxt_9825, target_6)
and func_7(vtlen_9826, target_7)
and func_8(vctxt_9825, vtlen_9826, target_8)
and func_9(vctxt_9825, vtlen_9826, target_9)
and vctxt_9825.getType().hasName("xmlParserCtxtPtr")
and vtlen_9826.getType().hasName("int")
and vctxt_9825.getFunction() = func
and vtlen_9826.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
