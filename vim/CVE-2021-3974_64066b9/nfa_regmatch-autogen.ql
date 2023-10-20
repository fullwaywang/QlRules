/**
 * @name vim-64066b9acd9f8cffdf4840f797748f938a13f2d6-nfa_regmatch
 * @id cpp/vim/64066b9acd9f8cffdf4840f797748f938a13f2d6/nfa-regmatch
 * @description vim-64066b9acd9f8cffdf4840f797748f938a13f2d6-src/regexp_nfa.c-nfa_regmatch CVE-2021-3974
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrex, ValueFieldAccess target_1, ConditionalExpr target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="reg_match"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="line"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("reg_getline")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="lnum"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="input"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="line"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_1.getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrex, ValueFieldAccess target_1) {
		target_1.getTarget().getName()="reg_buf"
		and target_1.getQualifier().(VariableAccess).getTarget()=vrex
}

predicate func_2(Variable vrex, ConditionalExpr target_2) {
		target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="lnum"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="lnum"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="reg_firstlnum"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="col"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2147483647"
		and target_2.getThen().(FunctionCall).getTarget().hasName("strlen")
		and target_2.getThen().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("reg_getline")
		and target_2.getThen().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="lnum"
		and target_2.getThen().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(SubExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="reg_firstlnum"
		and target_2.getThen().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vrex
		and target_2.getElse().(PointerFieldAccess).getTarget().getName()="col"
}

from Function func, Variable vrex, ValueFieldAccess target_1, ConditionalExpr target_2
where
not func_0(vrex, target_1, target_2)
and func_1(vrex, target_1)
and func_2(vrex, target_2)
and vrex.getType().hasName("regexec_T")
and not vrex.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
