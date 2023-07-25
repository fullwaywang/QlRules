/**
 * @name neomutt-fa1db5785e5cfd9d3cd27b7571b9fe268d2ec2dc-mutt_seqset_iterator_next
 * @id cpp/neomutt/fa1db5785e5cfd9d3cd27b7571b9fe268d2ec2dc/mutt-seqset-iterator-next
 * @description neomutt-fa1db5785e5cfd9d3cd27b7571b9fe268d2ec2dc-imap/util.c-mutt_seqset_iterator_next CVE-2021-32055
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter viter_1102, ExprStmt target_4, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="substr_cur"
		and target_0.getQualifier().(VariableAccess).getTarget()=viter_1102
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Parameter viter_1102, NotExpr target_5, WhileStmt target_1) {
		target_1.getCondition().(NotExpr).getOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="substr_cur"
		and target_1.getCondition().(NotExpr).getOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_1102
		and target_1.getStmt().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="substr_cur"
		and target_1.getStmt().(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_1102
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
}

predicate func_2(Parameter viter_1102, ExprStmt target_6, FunctionCall target_7, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="substr_end"
		and target_2.getQualifier().(VariableAccess).getTarget()=viter_1102
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(VariableAccess).getLocation())
		and target_2.getQualifier().(VariableAccess).getLocation().isBefore(target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_4(Parameter viter_1102, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="substr_end"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_1102
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strchr")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="substr_cur"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_1102
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(CharLiteral).getValue()="44"
}

predicate func_5(Parameter viter_1102, NotExpr target_5) {
		target_5.getOperand().(PointerFieldAccess).getTarget().getName()="in_range"
		and target_5.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_1102
}

predicate func_6(Parameter viter_1102, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="substr_end"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_1102
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="eostr"
		and target_6.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_1102
}

predicate func_7(Parameter viter_1102, FunctionCall target_7) {
		target_7.getTarget().hasName("strchr")
		and target_7.getArgument(0).(PointerFieldAccess).getTarget().getName()="substr_cur"
		and target_7.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_1102
		and target_7.getArgument(1).(CharLiteral).getValue()="58"
}

from Function func, Parameter viter_1102, PointerFieldAccess target_0, WhileStmt target_1, PointerFieldAccess target_2, ExprStmt target_4, NotExpr target_5, ExprStmt target_6, FunctionCall target_7
where
func_0(viter_1102, target_4, target_0)
and func_1(viter_1102, target_5, target_1)
and func_2(viter_1102, target_6, target_7, target_2)
and func_4(viter_1102, target_4)
and func_5(viter_1102, target_5)
and func_6(viter_1102, target_6)
and func_7(viter_1102, target_7)
and viter_1102.getType().hasName("SeqsetIterator *")
and viter_1102.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
