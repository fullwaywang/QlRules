/**
 * @name libxml2-94691dc884d1a8ada39f073408b4bb92fe7fe882-xmlDumpElementContent
 * @id cpp/libxml2/94691dc884d1a8ada39f073408b4bb92fe7fe882/xmlDumpElementContent
 * @description libxml2-94691dc884d1a8ada39f073408b4bb92fe7fe882-valid.c-xmlDumpElementContent CVE-2017-5969
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcontent_1159, ExprStmt target_8, LogicalOrExpr target_4) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="c1"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vcontent_1159, ExprStmt target_9, LogicalOrExpr target_5) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="c2"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand() instanceof LogicalOrExpr
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vcontent_1159, ExprStmt target_10, LogicalOrExpr target_6) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="c1"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand() instanceof LogicalOrExpr
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_10.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vcontent_1159, ExprStmt target_11, LogicalOrExpr target_7) {
	exists(LogicalAndExpr target_3 |
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="c2"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand() instanceof LogicalOrExpr
		and target_3.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vcontent_1159, LogicalOrExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c1"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c1"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_4.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_5(Parameter vcontent_1159, LogicalOrExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c2"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c2"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ocur"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c2"
		and target_5.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_5.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Parameter vcontent_1159, LogicalOrExpr target_6) {
		target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c1"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c1"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_6.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_7(Parameter vcontent_1159, LogicalOrExpr target_7) {
		target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c2"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c2"
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="ocur"
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c2"
		and target_7.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_7.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_8(Parameter vcontent_1159, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("xmlBufferWriteCHAR")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlBufferPtr")
		and target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_8.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
}

predicate func_9(Parameter vcontent_1159, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("xmlDumpElementContent")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlBufferPtr")
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="c1"
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_9.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_10(Parameter vcontent_1159, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("xmlDumpElementContent")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlBufferPtr")
		and target_10.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="c2"
		and target_10.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_10.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_11(Parameter vcontent_1159, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("xmlDumpElementContent")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlBufferPtr")
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="c1"
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcontent_1159
		and target_11.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

from Function func, Parameter vcontent_1159, LogicalOrExpr target_4, LogicalOrExpr target_5, LogicalOrExpr target_6, LogicalOrExpr target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11
where
not func_0(vcontent_1159, target_8, target_4)
and not func_1(vcontent_1159, target_9, target_5)
and not func_2(vcontent_1159, target_10, target_6)
and not func_3(vcontent_1159, target_11, target_7)
and func_4(vcontent_1159, target_4)
and func_5(vcontent_1159, target_5)
and func_6(vcontent_1159, target_6)
and func_7(vcontent_1159, target_7)
and func_8(vcontent_1159, target_8)
and func_9(vcontent_1159, target_9)
and func_10(vcontent_1159, target_10)
and func_11(vcontent_1159, target_11)
and vcontent_1159.getType().hasName("xmlElementContentPtr")
and vcontent_1159.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
