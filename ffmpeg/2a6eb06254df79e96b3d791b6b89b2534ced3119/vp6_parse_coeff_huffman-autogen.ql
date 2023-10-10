/**
 * @name ffmpeg-2a6eb06254df79e96b3d791b6b89b2534ced3119-vp6_parse_coeff_huffman
 * @id cpp/ffmpeg/2a6eb06254df79e96b3d791b6b89b2534ced3119/vp6-parse-coeff-huffman
 * @description ffmpeg-2a6eb06254df79e96b3d791b6b89b2534ced3119-libavcodec/vp6.c-vp6_parse_coeff_huffman CVE-2011-4353
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcoeff_idx_370, ExprStmt target_4, LogicalAndExpr target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcoeff_idx_370
		and target_0.getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcoeff_idx_370, VariableAccess target_1) {
		target_1.getTarget()=vcoeff_idx_370
		and target_1.getParent().(LTExpr).getGreaterOperand().(Literal).getValue()="64"
}

predicate func_3(Variable vcoeff_idx_370, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vcoeff_idx_370
		and target_3.getGreaterOperand() instanceof Literal
}

predicate func_4(Variable vcoeff_idx_370, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcoeff_idx_370
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_5(Variable vcoeff_idx_370, LogicalAndExpr target_5) {
		target_5.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcoeff_idx_370
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
		and target_5.getAnOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="nb_null"
		and target_5.getAnOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("VP56Context *")
		and target_5.getAnOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcoeff_idx_370
		and target_5.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vcoeff_idx_370, VariableAccess target_1, RelationalOperation target_3, ExprStmt target_4, LogicalAndExpr target_5
where
not func_0(vcoeff_idx_370, target_4, target_5)
and func_1(vcoeff_idx_370, target_1)
and func_3(vcoeff_idx_370, target_3)
and func_4(vcoeff_idx_370, target_4)
and func_5(vcoeff_idx_370, target_5)
and vcoeff_idx_370.getType().hasName("int")
and vcoeff_idx_370.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
