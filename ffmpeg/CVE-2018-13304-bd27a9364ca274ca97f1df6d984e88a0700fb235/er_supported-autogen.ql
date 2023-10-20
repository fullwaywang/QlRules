/**
 * @name ffmpeg-bd27a9364ca274ca97f1df6d984e88a0700fb235-er_supported
 * @id cpp/ffmpeg/bd27a9364ca274ca97f1df6d984e88a0700fb235/er-supported
 * @description ffmpeg-bd27a9364ca274ca97f1df6d984e88a0700fb235-libavcodec/error_resilience.c-er_supported CVE-2018-13304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_813, ReturnStmt target_2, LogicalOrExpr target_0) {
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="hwaccel"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_813
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="decode_slice"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hwaccel"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_813
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="f"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cur_pic"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_813
		and target_0.getAnOperand().(ValueFieldAccess).getTarget().getName()="field_picture"
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cur_pic"
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_813
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_1(Parameter vs_813, ReturnStmt target_2, LogicalOrExpr target_1) {
		target_1.getAnOperand() instanceof LogicalOrExpr
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="profile"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_813
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="14"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(ReturnStmt target_2) {
		target_2.getExpr().(Literal).getValue()="0"
}

from Function func, Parameter vs_813, LogicalOrExpr target_0, LogicalOrExpr target_1, ReturnStmt target_2
where
func_0(vs_813, target_2, target_0)
and func_1(vs_813, target_2, target_1)
and func_2(target_2)
and vs_813.getType().hasName("ERContext *")
and vs_813.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
