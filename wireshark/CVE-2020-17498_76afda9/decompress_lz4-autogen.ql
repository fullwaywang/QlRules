/**
 * @name wireshark-76afda963de4f0b9be24f2d8e873990a5cbf221b-decompress_lz4
 * @id cpp/wireshark/76afda963de4f0b9be24f2d8e873990a5cbf221b/decompress-lz4
 * @description wireshark-76afda963de4f0b9be24f2d8e873990a5cbf221b-epan/dissectors/packet-kafka.c-decompress_lz4 CVE-2020-17498
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcomposite_tvb_1307, EqualityOperation target_12, FunctionCall target_0) {
		target_0.getTarget().hasName("tvb_free_chain")
		and not target_0.getTarget().hasName("tvb_composite_finalize")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vcomposite_tvb_1307
		and target_12.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
}

predicate func_1(Variable vret_1309, ExprStmt target_13, ReturnStmt target_14, Literal target_1) {
		target_1.getValue()="0"
		and not target_1.getValue()="1"
		and target_1.getParent().(EQExpr).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_1309
		and target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getParent().(EQExpr).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_1.getParent().(EQExpr).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_14.getExpr().(VariableAccess).getLocation())
}

predicate func_2(Variable vcomposite_tvb_1307, BlockStmt target_7) {
	exists(NotExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vcomposite_tvb_1307
		and target_2.getParent().(IfStmt).getThen()=target_7)
}

predicate func_4(Variable vret_1309, ExprStmt target_13, ReturnStmt target_14, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_1309
		and target_4.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_4.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_4.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_4.getElse() instanceof BlockStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_4)
		and target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_14.getExpr().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vdecompressed_tvb_1300, Variable vcomposite_tvb_1307, Function func, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdecompressed_tvb_1300
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcomposite_tvb_1307
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

predicate func_6(Parameter vdecompressed_offset_1300, Function func, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdecompressed_offset_1300
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Parameter vpinfo_1300, EqualityOperation target_16, BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("col_append_str")
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cinfo"
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpinfo_1300
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()=" [lz4 decompression failed]"
		and target_7.getParent().(IfStmt).getCondition()=target_16
}

predicate func_8(Variable vcomposite_tvb_1307, Function func, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("tvb_composite_finalize")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcomposite_tvb_1307
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_9(Function func, FunctionCall target_9) {
		target_9.getTarget().hasName("tvb_new_composite")
		and target_9.getEnclosingFunction() = func
}

predicate func_11(Variable vcomposite_tvb_1307, BlockStmt target_17, VariableAccess target_11) {
		target_11.getTarget()=vcomposite_tvb_1307
		and target_11.getParent().(NEExpr).getAnOperand() instanceof Literal
		and target_11.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_17
}

predicate func_12(Variable vcomposite_tvb_1307, BlockStmt target_17, EqualityOperation target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vcomposite_tvb_1307
		and target_12.getAnOperand().(Literal).getValue()="0"
		and target_12.getParent().(IfStmt).getThen()=target_17
}

predicate func_13(Variable vret_1309, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_1309
		and target_13.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_14(Variable vret_1309, ReturnStmt target_14) {
		target_14.getExpr().(VariableAccess).getTarget()=vret_1309
}

predicate func_16(Variable vret_1309, EqualityOperation target_16) {
		target_16.getAnOperand().(VariableAccess).getTarget()=vret_1309
		and target_16.getAnOperand() instanceof Literal
}

predicate func_17(BlockStmt target_17) {
		target_17.getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
}

from Function func, Parameter vpinfo_1300, Parameter vdecompressed_tvb_1300, Parameter vdecompressed_offset_1300, Variable vcomposite_tvb_1307, Variable vret_1309, FunctionCall target_0, Literal target_1, ExprStmt target_5, ExprStmt target_6, BlockStmt target_7, ExprStmt target_8, FunctionCall target_9, VariableAccess target_11, EqualityOperation target_12, ExprStmt target_13, ReturnStmt target_14, EqualityOperation target_16, BlockStmt target_17
where
func_0(vcomposite_tvb_1307, target_12, target_0)
and func_1(vret_1309, target_13, target_14, target_1)
and not func_2(vcomposite_tvb_1307, target_7)
and not func_4(vret_1309, target_13, target_14, func)
and func_5(vdecompressed_tvb_1300, vcomposite_tvb_1307, func, target_5)
and func_6(vdecompressed_offset_1300, func, target_6)
and func_7(vpinfo_1300, target_16, target_7)
and func_8(vcomposite_tvb_1307, func, target_8)
and func_9(func, target_9)
and func_11(vcomposite_tvb_1307, target_17, target_11)
and func_12(vcomposite_tvb_1307, target_17, target_12)
and func_13(vret_1309, target_13)
and func_14(vret_1309, target_14)
and func_16(vret_1309, target_16)
and func_17(target_17)
and vpinfo_1300.getType().hasName("packet_info *")
and vdecompressed_tvb_1300.getType().hasName("tvbuff_t **")
and vdecompressed_offset_1300.getType().hasName("int *")
and vcomposite_tvb_1307.getType().hasName("tvbuff_t *")
and vret_1309.getType().hasName("int")
and vpinfo_1300.getParentScope+() = func
and vdecompressed_tvb_1300.getParentScope+() = func
and vdecompressed_offset_1300.getParentScope+() = func
and vcomposite_tvb_1307.getParentScope+() = func
and vret_1309.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
