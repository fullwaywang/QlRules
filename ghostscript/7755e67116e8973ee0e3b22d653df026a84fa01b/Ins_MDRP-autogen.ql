/**
 * @name ghostscript-7755e67116e8973ee0e3b22d653df026a84fa01b-Ins_MDRP
 * @id cpp/ghostscript/7755e67116e8973ee0e3b22d653df026a84fa01b/Ins-MDRP
 * @description ghostscript-7755e67116e8973ee0e3b22d653df026a84fa01b-base/ttinterp.c-Ins_MDRP CVE-2017-9726
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexc_3765, PointerDereferenceExpr target_2) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="rp0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="GS"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_3765
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="rp0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="GS"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_3765
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="n_points"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="zp0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_3765
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vargs_3765, Parameter vexc_3765, LogicalOrExpr target_1) {
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargs_3765
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargs_3765
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="n_points"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="zp1"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_3765
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
}

predicate func_2(Parameter vexc_3765, PointerDereferenceExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vexc_3765
}

from Function func, Parameter vargs_3765, Parameter vexc_3765, LogicalOrExpr target_1, PointerDereferenceExpr target_2
where
not func_0(vexc_3765, target_2)
and func_1(vargs_3765, vexc_3765, target_1)
and func_2(vexc_3765, target_2)
and vargs_3765.getType().hasName("PStorage")
and vexc_3765.getType().hasName("PExecution_Context")
and vargs_3765.getFunction() = func
and vexc_3765.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
