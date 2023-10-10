/**
 * @name postgresql-87b2ebd-get_row_security_policies
 * @id cpp/postgresql/87b2ebd/get-row-security-policies
 * @description postgresql-87b2ebd-src/backend/rewrite/rowsecurity.c-get_row_security_policies CVE-2017-15099
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrte_107, Parameter vrt_index_107, Parameter vwithCheckOptions_108, Parameter vhasSubLinks_109, Variable vrel_113, LogicalAndExpr target_3, BitwiseAndExpr target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="requiredPerms"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrte_107
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="2"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_113
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_107
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("List *")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getType().hasName("List *")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_108
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_109
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(8)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(BitwiseAndExpr target_4, Function func, DeclStmt target_1) {
		target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func
}

predicate func_2(BitwiseAndExpr target_4, Function func, DeclStmt target_2) {
		target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_2.getEnclosingFunction() = func
}

predicate func_3(LogicalAndExpr target_3) {
		target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("CmdType")
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="onConflict"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Query *")
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="action"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="onConflict"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Query *")
}

predicate func_4(Parameter vrte_107, BitwiseAndExpr target_4) {
		target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="requiredPerms"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vrte_107
		and target_4.getRightOperand().(BinaryBitwiseOperation).getValue()="2"
}

predicate func_5(Parameter vrt_index_107, Parameter vwithCheckOptions_108, Parameter vhasSubLinks_109, Variable vrel_113, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("add_with_check_options")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_113
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrt_index_107
		and target_5.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("List *")
		and target_5.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("List *")
		and target_5.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vwithCheckOptions_108
		and target_5.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vhasSubLinks_109
		and target_5.getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="0"
}

predicate func_6(Variable vrel_113, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("relation_close")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrel_113
		and target_6.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

from Function func, Parameter vrte_107, Parameter vrt_index_107, Parameter vwithCheckOptions_108, Parameter vhasSubLinks_109, Variable vrel_113, DeclStmt target_1, DeclStmt target_2, LogicalAndExpr target_3, BitwiseAndExpr target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(vrte_107, vrt_index_107, vwithCheckOptions_108, vhasSubLinks_109, vrel_113, target_3, target_4, target_5, target_6)
and func_1(target_4, func, target_1)
and func_2(target_4, func, target_2)
and func_3(target_3)
and func_4(vrte_107, target_4)
and func_5(vrt_index_107, vwithCheckOptions_108, vhasSubLinks_109, vrel_113, target_5)
and func_6(vrel_113, target_6)
and vrte_107.getType().hasName("RangeTblEntry *")
and vrt_index_107.getType().hasName("int")
and vwithCheckOptions_108.getType().hasName("List **")
and vhasSubLinks_109.getType().hasName("bool *")
and vrel_113.getType().hasName("Relation")
and vrte_107.getFunction() = func
and vrt_index_107.getFunction() = func
and vwithCheckOptions_108.getFunction() = func
and vhasSubLinks_109.getFunction() = func
and vrel_113.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
