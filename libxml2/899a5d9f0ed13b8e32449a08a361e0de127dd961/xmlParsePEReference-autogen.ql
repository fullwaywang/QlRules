/**
 * @name libxml2-899a5d9f0ed13b8e32449a08a361e0de127dd961-xmlParsePEReference
 * @id cpp/libxml2/899a5d9f0ed13b8e32449a08a361e0de127dd961/xmlParsePEReference
 * @description libxml2-899a5d9f0ed13b8e32449a08a361e0de127dd961-parser.c-xmlParsePEReference CVE-2017-16932
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vinput_7829, RelationalOperation target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("xmlFreeInputStream")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinput_7829
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2)
}

predicate func_1(RelationalOperation target_2, Function func, ReturnStmt target_1) {
		target_1.getParent().(IfStmt).getCondition()=target_2
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vinput_7829, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(FunctionCall).getTarget().hasName("xmlPushInput")
		and target_2.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("xmlParserCtxtPtr")
		and target_2.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinput_7829
		and target_2.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Variable vinput_7829, ReturnStmt target_1, RelationalOperation target_2
where
not func_0(vinput_7829, target_2)
and func_1(target_2, func, target_1)
and func_2(vinput_7829, target_2)
and vinput_7829.getType().hasName("xmlParserInputPtr")
and vinput_7829.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
