/**
 * @name imagemagick-fc43974d34318c834fbf78570ca1a3764ed8c7d7-ReadWPGImage
 * @id cpp/imagemagick/fc43974d34318c834fbf78570ca1a3764ed8c7d7/ReadWPGImage
 * @description imagemagick-fc43974d34318c834fbf78570ca1a3764ed8c7d7-coders/wpg.c-ReadWPGImage CVE-2016-5688
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_6, Function func) {
	exists(BreakStmt target_0 |
		target_0.toString() = "break;"
		and target_0.getParent().(IfStmt).getCondition()=target_6
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vexception_853, Variable vimage_934, Variable vstatus_937, ValueFieldAccess target_7, ExprStmt target_8, NotExpr target_9, ExprStmt target_3, LogicalAndExpr target_10, EqualityOperation target_11) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_937
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("SetImageExtent")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_934
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="columns"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_934
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="rows"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_934
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vexception_853
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_9.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_2(Variable vstatus_937, ValueFieldAccess target_7) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstatus_937
		and target_2.getThen().(BreakStmt).toString() = "break;"
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7)
}

predicate func_3(Parameter vexception_853, Variable vimage_934, Variable vstatus_937, Function func, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_937
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("SetImageExtent")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_934
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="columns"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_934
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="rows"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_934
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vexception_853
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Variable vimage_934, VariableAccess target_4) {
		target_4.getTarget()=vimage_934
		and target_4.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr() instanceof FunctionCall
}

predicate func_5(Variable vimage_934, EqualityOperation target_6, ReturnStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_934
		and target_5.getParent().(IfStmt).getCondition()=target_6
}

predicate func_6(Variable vstatus_937, EqualityOperation target_6) {
		target_6.getAnOperand().(VariableAccess).getTarget()=vstatus_937
}

predicate func_7(ValueFieldAccess target_7) {
		target_7.getTarget().getName()="RecType"
}

predicate func_8(Parameter vexception_853, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_853
		and target_8.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_8.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ImproperImageHeader"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ImproperImageHeader"
		and target_8.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_8.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
}

predicate func_9(Parameter vexception_853, Variable vimage_934, NotExpr target_9) {
		target_9.getOperand().(FunctionCall).getTarget().hasName("AcquireImageColormap")
		and target_9.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_934
		and target_9.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="colors"
		and target_9.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_934
		and target_9.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vexception_853
}

predicate func_10(Variable vimage_934, LogicalAndExpr target_10) {
		target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="colors"
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_934
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="24"
}

predicate func_11(Variable vstatus_937, EqualityOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vstatus_937
}

from Function func, Parameter vexception_853, Variable vimage_934, Variable vstatus_937, ExprStmt target_3, VariableAccess target_4, ReturnStmt target_5, EqualityOperation target_6, ValueFieldAccess target_7, ExprStmt target_8, NotExpr target_9, LogicalAndExpr target_10, EqualityOperation target_11
where
not func_0(target_6, func)
and not func_1(vexception_853, vimage_934, vstatus_937, target_7, target_8, target_9, target_3, target_10, target_11)
and not func_2(vstatus_937, target_7)
and func_3(vexception_853, vimage_934, vstatus_937, func, target_3)
and func_4(vimage_934, target_4)
and func_5(vimage_934, target_6, target_5)
and func_6(vstatus_937, target_6)
and func_7(target_7)
and func_8(vexception_853, target_8)
and func_9(vexception_853, vimage_934, target_9)
and func_10(vimage_934, target_10)
and func_11(vstatus_937, target_11)
and vexception_853.getType().hasName("ExceptionInfo *")
and vimage_934.getType().hasName("Image *")
and vstatus_937.getType().hasName("unsigned int")
and vexception_853.getParentScope+() = func
and vimage_934.getParentScope+() = func
and vstatus_937.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
