/**
 * @name ffmpeg-4a80ebe491609e04110a1dd540a0ca79d3be3d04-decode_init
 * @id cpp/ffmpeg/4a80ebe491609e04110a1dd540a0ca79d3be3d04/decode-init
 * @description ffmpeg-4a80ebe491609e04110a1dd540a0ca79d3be3d04-libavcodec/indeo3.c-decode_init CVE-2012-2804
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vctx_1024, Parameter vavctx_1022, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="width"
		and target_0.getQualifier().(VariableAccess).getTarget()=vavctx_1022
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_1024
}

predicate func_1(Variable vctx_1024, Parameter vavctx_1022, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="height"
		and target_1.getQualifier().(VariableAccess).getTarget()=vavctx_1022
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_1024
}

predicate func_2(Variable vctx_1024, Parameter vavctx_1022, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_1024
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_1022
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vctx_1024, Parameter vavctx_1022, Function func, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_1024
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_1022
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

from Function func, Variable vctx_1024, Parameter vavctx_1022, PointerFieldAccess target_0, PointerFieldAccess target_1, ExprStmt target_2, ExprStmt target_3
where
func_0(vctx_1024, vavctx_1022, target_0)
and func_1(vctx_1024, vavctx_1022, target_1)
and func_2(vctx_1024, vavctx_1022, func, target_2)
and func_3(vctx_1024, vavctx_1022, func, target_3)
and vctx_1024.getType().hasName("Indeo3DecodeContext *")
and vavctx_1022.getType().hasName("AVCodecContext *")
and vctx_1024.(LocalVariable).getFunction() = func
and vavctx_1022.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
