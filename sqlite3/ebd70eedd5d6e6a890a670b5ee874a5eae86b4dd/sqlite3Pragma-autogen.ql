/**
 * @name sqlite3-ebd70eedd5d6e6a890a670b5ee874a5eae86b4dd-sqlite3Pragma
 * @id cpp/sqlite3/ebd70eedd5d6e6a890a670b5ee874a5eae86b4dd/sqlite3Pragma
 * @description sqlite3-ebd70eedd5d6e6a890a670b5ee874a5eae86b4dd-src/pragma.c-sqlite3Pragma CVE-2019-19646
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vv_345, ExprStmt target_2, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="opcode"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("sqlite3VdbeGetOp")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vv_345
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="88"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vv_345, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("sqlite3VdbeChangeP5")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vv_345
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="128"
}

predicate func_2(Variable vv_345, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("sqlite3ExprCodeGetColumnOfTable")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vv_345
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("Table *")
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="3"
}

from Function func, Variable vv_345, ExprStmt target_1, ExprStmt target_2
where
not func_0(vv_345, target_2, target_1)
and func_1(vv_345, target_1)
and func_2(vv_345, target_2)
and vv_345.getType().hasName("Vdbe *")
and vv_345.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
