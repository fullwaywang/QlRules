/**
 * @name linux-979d63d50c0c0f7bc537bf821e056cc9fe5abd38-do_check
 * @id cpp/linux/979d63d50c0c0f7bc537bf821e056cc9fe5abd38/do_check
 * @description linux-979d63d50c0c0f7bc537bf821e056cc9fe5abd38-do_check 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="\nfrom %d to %d: safe\n"
		and not target_0.getValue()="\nfrom %d to %d%s: safe\n"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(StringLiteral target_1 |
		target_1.getValue()="\nfrom %d to %d:"
		and not target_1.getValue()="\nfrom %d to %d%s:"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vstate_5690) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(PointerFieldAccess).getTarget().getName()="speculative"
		and target_2.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_5690)
}

predicate func_3(Parameter venv_5688) {
	exists(ConditionalExpr target_3 |
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="speculative"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cur_state"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venv_5688
		and target_3.getThen().(StringLiteral).getValue()=" (speculative execution)"
		and target_3.getElse().(StringLiteral).getValue()=""
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("verbose")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=venv_5688
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\nfrom %d to %d%s: safe\n"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="prev_insn_idx"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venv_5688
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="insn_idx"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venv_5688)
}

predicate func_4(Parameter venv_5688) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("verbose")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=venv_5688
		and target_4.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="\nfrom %d to %d%s:"
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="prev_insn_idx"
		and target_4.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venv_5688
		and target_4.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="insn_idx"
		and target_4.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venv_5688
		and target_4.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="speculative"
		and target_4.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cur_state"
		and target_4.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venv_5688
		and target_4.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(StringLiteral).getValue()=" (speculative execution)"
		and target_4.getExpr().(FunctionCall).getArgument(4).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_4.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="level"
		and target_4.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="log"
		and target_4.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=venv_5688
		and target_4.getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="1")
}

predicate func_6(Variable vstate_5690) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="frame"
		and target_6.getQualifier().(VariableAccess).getTarget()=vstate_5690)
}

predicate func_7(Parameter venv_5688) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="insn_idx"
		and target_7.getQualifier().(VariableAccess).getTarget()=venv_5688)
}

from Function func, Variable vstate_5690, Parameter venv_5688
where
func_0(func)
and func_1(func)
and not func_2(vstate_5690)
and not func_3(venv_5688)
and not func_4(venv_5688)
and vstate_5690.getType().hasName("bpf_verifier_state *")
and func_6(vstate_5690)
and venv_5688.getType().hasName("bpf_verifier_env *")
and func_7(venv_5688)
and vstate_5690.getParentScope+() = func
and venv_5688.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
