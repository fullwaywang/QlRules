/**
 * @name libplist-32ee5213fe64f1e10ec76c1ee861ee6f233120dd-parse_bin_node
 * @id cpp/libplist/32ee5213fe64f1e10ec76c1ee861ee6f233120dd/parse-bin-node
 * @description libplist-32ee5213fe64f1e10ec76c1ee861ee6f233120dd-src/bplist.c-parse_bin_node CVE-2017-6436
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vobject_560, Variable vsize_563, BlockStmt target_10, FunctionCall target_11, RelationalOperation target_5) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(IfStmt).getThen()=target_10
		and target_11.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vobject_560, Variable vsize_563, BlockStmt target_12, FunctionCall target_13, RelationalOperation target_6) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_1.getAnOperand() instanceof RelationalOperation
		and target_1.getParent().(IfStmt).getThen()=target_12
		and target_13.getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vobject_560, Variable vsize_563, BlockStmt target_14, FunctionCall target_15, RelationalOperation target_7, RelationalOperation target_16) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vsize_563
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_2.getAnOperand() instanceof RelationalOperation
		and target_2.getParent().(IfStmt).getThen()=target_14
		and target_15.getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_16.getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vobject_560, Variable vsize_563, BlockStmt target_17, FunctionCall target_18, RelationalOperation target_8) {
	exists(LogicalOrExpr target_3 |
		target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_3.getAnOperand() instanceof RelationalOperation
		and target_3.getParent().(IfStmt).getThen()=target_17
		and target_18.getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_8.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vobject_560, Variable vsize_563, BlockStmt target_19, FunctionCall target_20, RelationalOperation target_9) {
	exists(LogicalOrExpr target_4 |
		target_4.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_4.getAnOperand() instanceof RelationalOperation
		and target_4.getParent().(IfStmt).getThen()=target_19
		and target_20.getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_9.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vbplist_560, Parameter vobject_560, Variable vsize_563, BlockStmt target_10, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_5.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_5.getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_5.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_5.getParent().(IfStmt).getThen()=target_10
}

predicate func_6(Parameter vbplist_560, Parameter vobject_560, Variable vsize_563, BlockStmt target_12, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_6.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_6.getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_6.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_6.getParent().(IfStmt).getThen()=target_12
}

predicate func_7(Parameter vbplist_560, Parameter vobject_560, Variable vsize_563, BlockStmt target_14, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_7.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vsize_563
		and target_7.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_7.getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_7.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_7.getParent().(IfStmt).getThen()=target_14
}

predicate func_8(Parameter vbplist_560, Parameter vobject_560, Variable vsize_563, BlockStmt target_17, RelationalOperation target_8) {
		 (target_8 instanceof GTExpr or target_8 instanceof LTExpr)
		and target_8.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_8.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_8.getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_8.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_8.getParent().(IfStmt).getThen()=target_17
}

predicate func_9(Parameter vbplist_560, Parameter vobject_560, Variable vsize_563, BlockStmt target_19, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_9.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_9.getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_9.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_9.getParent().(IfStmt).getThen()=target_19
}

predicate func_10(BlockStmt target_10) {
		target_10.getStmt(0).(EmptyStmt).toString() = ";"
		and target_10.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_11(Parameter vobject_560, Variable vsize_563, FunctionCall target_11) {
		target_11.getTarget().hasName("parse_date_node")
		and target_11.getArgument(0).(VariableAccess).getTarget()=vobject_560
		and target_11.getArgument(1).(VariableAccess).getTarget()=vsize_563
}

predicate func_12(BlockStmt target_12) {
		target_12.getStmt(0).(EmptyStmt).toString() = ";"
		and target_12.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_13(Parameter vobject_560, Variable vsize_563, FunctionCall target_13) {
		target_13.getTarget().hasName("parse_data_node")
		and target_13.getArgument(0).(VariableAccess).getTarget()=vobject_560
		and target_13.getArgument(1).(VariableAccess).getTarget()=vsize_563
}

predicate func_14(BlockStmt target_14) {
		target_14.getStmt(0).(EmptyStmt).toString() = ";"
		and target_14.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_15(Parameter vobject_560, Variable vsize_563, FunctionCall target_15) {
		target_15.getTarget().hasName("parse_string_node")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vobject_560
		and target_15.getArgument(1).(VariableAccess).getTarget()=vsize_563
}

predicate func_16(Variable vsize_563, RelationalOperation target_16) {
		 (target_16 instanceof GTExpr or target_16 instanceof LTExpr)
		and target_16.getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vsize_563
		and target_16.getLesserOperand().(MulExpr).getRightOperand().(Literal).getValue()="2"
		and target_16.getGreaterOperand().(VariableAccess).getTarget()=vsize_563
}

predicate func_17(BlockStmt target_17) {
		target_17.getStmt(0).(EmptyStmt).toString() = ";"
		and target_17.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_18(Parameter vobject_560, Variable vsize_563, FunctionCall target_18) {
		target_18.getTarget().hasName("parse_unicode_node")
		and target_18.getArgument(0).(VariableAccess).getTarget()=vobject_560
		and target_18.getArgument(1).(VariableAccess).getTarget()=vsize_563
}

predicate func_19(BlockStmt target_19) {
		target_19.getStmt(0).(EmptyStmt).toString() = ";"
		and target_19.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_20(Parameter vobject_560, Variable vsize_563, FunctionCall target_20) {
		target_20.getTarget().hasName("parse_uid_node")
		and target_20.getArgument(0).(VariableAccess).getTarget()=vobject_560
		and target_20.getArgument(1).(VariableAccess).getTarget()=vsize_563
}

from Function func, Parameter vbplist_560, Parameter vobject_560, Variable vsize_563, RelationalOperation target_5, RelationalOperation target_6, RelationalOperation target_7, RelationalOperation target_8, RelationalOperation target_9, BlockStmt target_10, FunctionCall target_11, BlockStmt target_12, FunctionCall target_13, BlockStmt target_14, FunctionCall target_15, RelationalOperation target_16, BlockStmt target_17, FunctionCall target_18, BlockStmt target_19, FunctionCall target_20
where
not func_0(vobject_560, vsize_563, target_10, target_11, target_5)
and not func_1(vobject_560, vsize_563, target_12, target_13, target_6)
and not func_2(vobject_560, vsize_563, target_14, target_15, target_7, target_16)
and not func_3(vobject_560, vsize_563, target_17, target_18, target_8)
and not func_4(vobject_560, vsize_563, target_19, target_20, target_9)
and func_5(vbplist_560, vobject_560, vsize_563, target_10, target_5)
and func_6(vbplist_560, vobject_560, vsize_563, target_12, target_6)
and func_7(vbplist_560, vobject_560, vsize_563, target_14, target_7)
and func_8(vbplist_560, vobject_560, vsize_563, target_17, target_8)
and func_9(vbplist_560, vobject_560, vsize_563, target_19, target_9)
and func_10(target_10)
and func_11(vobject_560, vsize_563, target_11)
and func_12(target_12)
and func_13(vobject_560, vsize_563, target_13)
and func_14(target_14)
and func_15(vobject_560, vsize_563, target_15)
and func_16(vsize_563, target_16)
and func_17(target_17)
and func_18(vobject_560, vsize_563, target_18)
and func_19(target_19)
and func_20(vobject_560, vsize_563, target_20)
and vbplist_560.getType().hasName("bplist_data *")
and vobject_560.getType().hasName("const char **")
and vsize_563.getType().hasName("uint64_t")
and vbplist_560.getParentScope+() = func
and vobject_560.getParentScope+() = func
and vsize_563.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
