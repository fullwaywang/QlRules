/**
 * @name ghostscript-98f6da60b9d463c617e631fc254cf6d66f2e8e3c-Ins_IP
 * @id cpp/ghostscript/98f6da60b9d463c617e631fc254cf6d66f2e8e3c/Ins-IP
 * @description ghostscript-98f6da60b9d463c617e631fc254cf6d66f2e8e3c-base/ttinterp.c-Ins_IP CVE-2017-9612
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexc_4124, BlockStmt target_2, PointerDereferenceExpr target_3) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="rp1"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="GS"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="rp1"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="GS"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="n_points"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="zp0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="rp2"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="GS"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_4124
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="rp2"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="GS"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_4124
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="n_points"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="zp1"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_4124
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vexc_4124, BlockStmt target_2, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(ValueFieldAccess).getTarget().getName()="top"
		and target_1.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_4124
		and target_1.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="loop"
		and target_1.getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="GS"
		and target_1.getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_4124
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vexc_4124, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="error"
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexc_4124
		and target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1032"
}

predicate func_3(Parameter vexc_4124, PointerDereferenceExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vexc_4124
}

from Function func, Parameter vexc_4124, RelationalOperation target_1, BlockStmt target_2, PointerDereferenceExpr target_3
where
not func_0(vexc_4124, target_2, target_3)
and func_1(vexc_4124, target_2, target_1)
and func_2(vexc_4124, target_2)
and func_3(vexc_4124, target_3)
and vexc_4124.getType().hasName("PExecution_Context")
and vexc_4124.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
