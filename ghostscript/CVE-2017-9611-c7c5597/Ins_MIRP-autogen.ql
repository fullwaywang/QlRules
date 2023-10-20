/**
 * @name ghostscript-c7c55972758a93350882c32147801a3485b010fe-Ins_MIRP
 * @id cpp/ghostscript/c7c55972758a93350882c32147801a3485b010fe/Ins-MIRP
 * @description ghostscript-c7c55972758a93350882c32147801a3485b010fe-base/ttinterp.c-Ins_MIRP CVE-2017-9611
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexc_3845, BlockStmt target_2, PointerDereferenceExpr target_3) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="rp0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="GS"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_3845
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="rp0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="GS"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_3845
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="n_points"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="zp0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_3845
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vargs_3845, Parameter vexc_3845, BlockStmt target_2, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargs_3845
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargs_3845
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="n_points"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="zp1"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_3845
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargs_3845
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vargs_3845
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="cvtSize"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_3845
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vexc_3845, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="error"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_3845
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1032"
}

predicate func_3(Parameter vexc_3845, PointerDereferenceExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vexc_3845
}

from Function func, Parameter vargs_3845, Parameter vexc_3845, LogicalOrExpr target_1, BlockStmt target_2, PointerDereferenceExpr target_3
where
not func_0(vexc_3845, target_2, target_3)
and func_1(vargs_3845, vexc_3845, target_2, target_1)
and func_2(vexc_3845, target_2)
and func_3(vexc_3845, target_3)
and vargs_3845.getType().hasName("PStorage")
and vexc_3845.getType().hasName("PExecution_Context")
and vargs_3845.getFunction() = func
and vexc_3845.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
