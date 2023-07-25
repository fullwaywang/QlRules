/**
 * @name ffmpeg-c94f9e854228e0ea00e1de8769d8d3f7cab84a55-av_reallocp_array
 * @id cpp/ffmpeg/c94f9e854228e0ea00e1de8769d8d3f7cab84a55/av-reallocp-array
 * @description ffmpeg-c94f9e854228e0ea00e1de8769d8d3f7cab84a55-libavutil/mem.c-av_reallocp_array CVE-2013-4265
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vptrptr_192, ReturnStmt target_3, NotExpr target_0) {
		target_0.getOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptrptr_192
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_1(Parameter vsize_190, VariableAccess target_1) {
		target_1.getTarget()=vsize_190
}

predicate func_2(Parameter vnmemb_190, Parameter vsize_190, ReturnStmt target_3, NotExpr target_2) {
		target_2.getOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vnmemb_190
		and target_2.getOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vsize_190
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof NotExpr
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_3
}

predicate func_3(ReturnStmt target_3) {
		target_3.getExpr().(UnaryMinusExpr).getValue()="-12"
}

from Function func, Parameter vnmemb_190, Parameter vsize_190, Variable vptrptr_192, NotExpr target_0, VariableAccess target_1, NotExpr target_2, ReturnStmt target_3
where
func_0(vptrptr_192, target_3, target_0)
and func_1(vsize_190, target_1)
and func_2(vnmemb_190, vsize_190, target_3, target_2)
and func_3(target_3)
and vnmemb_190.getType().hasName("size_t")
and vsize_190.getType().hasName("size_t")
and vptrptr_192.getType().hasName("void **")
and vnmemb_190.getFunction() = func
and vsize_190.getFunction() = func
and vptrptr_192.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
