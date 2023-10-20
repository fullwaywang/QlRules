/**
 * @name ffmpeg-03d83ba34b2070878909eae18dfac0f519503777-gif_encode_close
 * @id cpp/ffmpeg/03d83ba34b2070878909eae18dfac0f519503777/gif-encode-close
 * @description ffmpeg-03d83ba34b2070878909eae18dfac0f519503777-libavcodec/gif.c-gif_encode_close CVE-2016-2330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_320, AddressOfExpr target_1, AddressOfExpr target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf_size"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_320
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_320, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_320
}

predicate func_2(Variable vs_320, AddressOfExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="last_frame"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_320
}

from Function func, Variable vs_320, AddressOfExpr target_1, AddressOfExpr target_2
where
not func_0(vs_320, target_1, target_2, func)
and func_1(vs_320, target_1)
and func_2(vs_320, target_2)
and vs_320.getType().hasName("GIFContext *")
and vs_320.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
