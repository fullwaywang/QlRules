/**
 * @name pcre2-26e92bc554db487f600a8178f9ad97b8b02e9345-pcre2_match_8
 * @id cpp/pcre2/26e92bc554db487f600a8178f9ad97b8b02e9345/pcre2-match-8
 * @description pcre2-26e92bc554db487f600a8178f9ad97b8b02e9345-pcre2_match_8 CVE-2017-8399
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmb_6025) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="stack_frames"
		and target_0.getQualifier().(VariableAccess).getTarget()=vmb_6025)
}

predicate func_1(Variable vframe_size_6019, Variable vmb_6025, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vframe_size_6019
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getValue()="1024"
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="frame_vector_size"
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmb_6025
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vframe_size_6019
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(Literal).getValue()="10"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="match_frames"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmb_6025
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getTarget().getName()="malloc"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memctl"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmb_6025
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="frame_vector_size"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmb_6025
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="memory_data"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memctl"
		and target_1.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmb_6025
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="match_frames"
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmb_6025
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="48"
		and (func.getEntryPoint().(BlockStmt).getStmt(61)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(61).getFollowingStmt()=target_1))
}

predicate func_6(Variable vframe_size_6019, Variable vmb_6025, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="frame_vector_size"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmb_6025
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(DivExpr).getLeftOperand().(Literal).getValue()="10240"
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vframe_size_6019
		and target_6.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vframe_size_6019
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_7(Variable vmb_6025, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="match_frames"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmb_6025
		and target_7.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="stack_frames"
		and target_7.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmb_6025
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7)
}

predicate func_8(Variable vframe_size_6019, Variable vmb_6025) {
	exists(MulExpr target_8 |
		target_8.getLeftOperand().(DivExpr).getLeftOperand().(Literal).getValue()="10240"
		and target_8.getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vframe_size_6019
		and target_8.getRightOperand().(VariableAccess).getTarget()=vframe_size_6019
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="frame_vector_size"
		and target_8.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmb_6025)
}

predicate func_9(Variable vmb_6025) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="frame_vector_size"
		and target_9.getQualifier().(VariableAccess).getTarget()=vmb_6025)
}

predicate func_10(Variable vmb_6025) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="stack_frames"
		and target_10.getQualifier().(VariableAccess).getTarget()=vmb_6025)
}

from Function func, Variable vframe_size_6019, Variable vmb_6025
where
func_0(vmb_6025)
and not func_1(vframe_size_6019, vmb_6025, func)
and func_6(vframe_size_6019, vmb_6025, func)
and func_7(vmb_6025, func)
and vframe_size_6019.getType().hasName("size_t")
and func_8(vframe_size_6019, vmb_6025)
and vmb_6025.getType().hasName("match_block_8 *")
and func_9(vmb_6025)
and func_10(vmb_6025)
and vframe_size_6019.getParentScope+() = func
and vmb_6025.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
