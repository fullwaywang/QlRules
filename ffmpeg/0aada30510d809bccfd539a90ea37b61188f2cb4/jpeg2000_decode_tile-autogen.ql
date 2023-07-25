/**
 * @name ffmpeg-0aada30510d809bccfd539a90ea37b61188f2cb4-jpeg2000_decode_tile
 * @id cpp/ffmpeg/0aada30510d809bccfd539a90ea37b61188f2cb4/jpeg2000-decode-tile
 * @description ffmpeg-0aada30510d809bccfd539a90ea37b61188f2cb4-libavcodec/jpeg2000dec.c-jpeg2000_decode_tile CVE-2016-2213
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vx_1761, Parameter vs_1758, RelationalOperation target_5, RelationalOperation target_6) {
	exists(ForStmt target_1 |
		target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx_1761
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vx_1761
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="ncomponents"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1758
		and target_1.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vx_1761
		and target_1.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(RelationalOperation target_5, Function func) {
	exists(BreakStmt target_2 |
		target_2.toString() = "break;"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vx_1761, Parameter vs_1758, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdef"
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1758
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vx_1761
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vx_1761
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_5(Parameter vs_1758, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="cdef"
		and target_5.getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1758
		and target_5.getLesserOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_5.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_6(Variable vx_1761, Parameter vs_1758, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vx_1761
		and target_6.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="ncomponents"
		and target_6.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1758
}

from Function func, Variable vx_1761, Parameter vs_1758, ExprStmt target_3, RelationalOperation target_5, RelationalOperation target_6
where
not func_1(vx_1761, vs_1758, target_5, target_6)
and not func_2(target_5, func)
and func_3(vx_1761, vs_1758, target_3)
and func_5(vs_1758, target_5)
and func_6(vx_1761, vs_1758, target_6)
and vx_1761.getType().hasName("int")
and vs_1758.getType().hasName("Jpeg2000DecoderContext *")
and vx_1761.getParentScope+() = func
and vs_1758.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
