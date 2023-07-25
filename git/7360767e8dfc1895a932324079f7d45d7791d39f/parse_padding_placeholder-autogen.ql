/**
 * @name git-7360767e8dfc1895a932324079f7d45d7791d39f-parse_padding_placeholder
 * @id cpp/git/7360767e8dfc1895a932324079f7d45d7791d39f/parse-padding-placeholder
 * @description git-7360767e8dfc1895a932324079f7d45d7791d39f-pretty.c-parse_padding_placeholder CVE-2022-41953
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstart_1119, Variable vend_1120, EqualityOperation target_3, PointerArithmeticOperation target_4, LogicalOrExpr target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vend_1120
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vend_1120
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstart_1119
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vwidth_1122, EqualityOperation target_3) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vwidth_1122
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(UnaryMinusExpr).getValue()="-16384"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vwidth_1122
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getValue()="16384"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3)
}

predicate func_2(Variable vstart_1119, Variable vend_1120, EqualityOperation target_3, IfStmt target_2) {
		target_2.getCondition().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vend_1120
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vend_1120
		and target_2.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstart_1119
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(EqualityOperation target_3) {
		target_3.getAnOperand().(CharLiteral).getValue()="40"
}

predicate func_4(Variable vstart_1119, PointerArithmeticOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vstart_1119
		and target_4.getAnOperand().(FunctionCall).getTarget().hasName("strcspn")
		and target_4.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstart_1119
		and target_4.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=",)"
}

predicate func_5(Variable vstart_1119, Variable vend_1120, LogicalOrExpr target_5) {
		target_5.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vend_1120
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vend_1120
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstart_1119
}

from Function func, Variable vstart_1119, Variable vend_1120, Variable vwidth_1122, IfStmt target_2, EqualityOperation target_3, PointerArithmeticOperation target_4, LogicalOrExpr target_5
where
not func_0(vstart_1119, vend_1120, target_3, target_4, target_5)
and not func_1(vwidth_1122, target_3)
and func_2(vstart_1119, vend_1120, target_3, target_2)
and func_3(target_3)
and func_4(vstart_1119, target_4)
and func_5(vstart_1119, vend_1120, target_5)
and vstart_1119.getType().hasName("const char *")
and vend_1120.getType().hasName("const char *")
and vwidth_1122.getType().hasName("int")
and vstart_1119.getParentScope+() = func
and vend_1120.getParentScope+() = func
and vwidth_1122.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
