/**
 * @name ffmpeg-c6939f65a116b1ffed345d29d8621ee4ffb32235-filter_slice
 * @id cpp/ffmpeg/c6939f65a116b1ffed345d29d8621ee4ffb32235/filter-slice
 * @description ffmpeg-c6939f65a116b1ffed345d29d8621ee4ffb32235-libavfilter/vf_transpose.c-filter_slice CVE-2018-6392
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_269, Variable vplane_273, BlockStmt target_4, ConditionalExpr target_5, ExprStmt target_6) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vplane_273
		and target_0.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="planes"
		and target_0.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_269
		and target_0.getParent().(ForStmt).getStmt()=target_4
		and target_0.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(VariableAccess).getLocation()))
}

/*predicate func_1(Variable vout_271, Variable vplane_273, BlockStmt target_4, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="data"
		and target_1.getQualifier().(VariableAccess).getTarget()=vout_271
		and target_1.getParent().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_273
		and target_1.getParent().(ArrayExpr).getParent().(ForStmt).getStmt()=target_4
}

*/
/*predicate func_2(Variable vout_271, Variable vplane_273, BlockStmt target_4, VariableAccess target_2) {
		target_2.getTarget()=vplane_273
		and target_2.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_271
		and target_2.getParent().(ArrayExpr).getParent().(ForStmt).getStmt()=target_4
}

*/
predicate func_3(Variable vout_271, Variable vplane_273, BlockStmt target_4, ConditionalExpr target_7, ArrayExpr target_3) {
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_271
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vplane_273
		and target_3.getParent().(ForStmt).getStmt()=target_4
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getThen().(UnaryMinusExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_4(Variable vout_271, Variable vplane_273, BlockStmt target_4) {
		target_4.getStmt(11).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_4.getStmt(11).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_271
		and target_4.getStmt(11).(ExprStmt).getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_273
		and target_4.getStmt(12).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_4.getStmt(12).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_271
		and target_4.getStmt(12).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vplane_273
}

predicate func_5(Variable vs_269, Variable vplane_273, ConditionalExpr target_5) {
		target_5.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vplane_273
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vplane_273
		and target_5.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_5.getThen().(PointerFieldAccess).getTarget().getName()="hsub"
		and target_5.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_269
		and target_5.getElse().(Literal).getValue()="0"
}

predicate func_6(Variable vplane_273, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vplane_273
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_7(Variable vout_271, ConditionalExpr target_7) {
		target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("__builtin_constant_p")
		and target_7.getThen().(UnaryMinusExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_7.getThen().(UnaryMinusExpr).getOperand().(BinaryBitwiseOperation).getLeftOperand().(UnaryMinusExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_271
		and target_7.getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_7.getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vout_271
		and target_7.getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_7.getElse().(BinaryBitwiseOperation).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

from Function func, Variable vs_269, Variable vout_271, Variable vplane_273, ArrayExpr target_3, BlockStmt target_4, ConditionalExpr target_5, ExprStmt target_6, ConditionalExpr target_7
where
not func_0(vs_269, vplane_273, target_4, target_5, target_6)
and func_3(vout_271, vplane_273, target_4, target_7, target_3)
and func_4(vout_271, vplane_273, target_4)
and func_5(vs_269, vplane_273, target_5)
and func_6(vplane_273, target_6)
and func_7(vout_271, target_7)
and vs_269.getType().hasName("TransContext *")
and vout_271.getType().hasName("AVFrame *")
and vplane_273.getType().hasName("int")
and vs_269.getParentScope+() = func
and vout_271.getParentScope+() = func
and vplane_273.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
