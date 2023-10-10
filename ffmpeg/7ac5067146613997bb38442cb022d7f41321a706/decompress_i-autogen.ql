/**
 * @name ffmpeg-7ac5067146613997bb38442cb022d7f41321a706-decompress_i
 * @id cpp/ffmpeg/7ac5067146613997bb38442cb022d7f41321a706/decompress-i
 * @description ffmpeg-7ac5067146613997bb38442cb022d7f41321a706-libavcodec/scpr.c-decompress_i CVE-2017-9995
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vy_298, Parameter vavctx_293, ExprStmt target_1, RelationalOperation target_2, RelationalOperation target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vy_298
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_293
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_2.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vy_298, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vy_298
}

predicate func_2(Parameter vavctx_293, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_293
		and target_2.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_3(Parameter vavctx_293, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getLesserOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_3.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_293
}

from Function func, Variable vy_298, Parameter vavctx_293, ExprStmt target_1, RelationalOperation target_2, RelationalOperation target_3
where
not func_0(vy_298, vavctx_293, target_1, target_2, target_3)
and func_1(vy_298, target_1)
and func_2(vavctx_293, target_2)
and func_3(vavctx_293, target_3)
and vy_298.getType().hasName("int")
and vavctx_293.getType().hasName("AVCodecContext *")
and vy_298.getParentScope+() = func
and vavctx_293.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
