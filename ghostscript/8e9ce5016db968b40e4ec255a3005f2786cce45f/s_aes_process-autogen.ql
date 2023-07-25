/**
 * @name ghostscript-8e9ce5016db968b40e4ec255a3005f2786cce45f-s_aes_process
 * @id cpp/ghostscript/8e9ce5016db968b40e4ec255a3005f2786cce45f/s-aes-process
 * @description ghostscript-8e9ce5016db968b40e4ec255a3005f2786cce45f-base/saes.c-s_aes_process CVE-2018-15911
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstate_96, EqualityOperation target_1, EqualityOperation target_2, LogicalOrExpr target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="ctx"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_96
		and target_0.getExpr().(FunctionCall).getArgument(1).(HexLiteral).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="560"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vstate_96, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_96
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Variable vstate_96, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="ctx"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_96
		and target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Variable vstate_96, LogicalOrExpr target_3) {
		target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="keylength"
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_96
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="keylength"
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_96
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
}

from Function func, Variable vstate_96, EqualityOperation target_1, EqualityOperation target_2, LogicalOrExpr target_3
where
not func_0(vstate_96, target_1, target_2, target_3)
and func_1(vstate_96, target_1)
and func_2(vstate_96, target_2)
and func_3(vstate_96, target_3)
and vstate_96.getType().hasName("stream_aes_state *const")
and vstate_96.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
