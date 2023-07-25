/**
 * @name cryptsetup-52f5cb8cedf22fb3e14c744814ec8af7614146c7-hdr_validate_segments
 * @id cpp/cryptsetup/52f5cb8cedf22fb3e14c744814ec8af7614146c7/hdr-validate-segments
 * @description cryptsetup-52f5cb8cedf22fb3e14c744814ec8af7614146c7-lib/luks2/luks2_json_metadata.c-hdr_validate_segments CVE-2020-14382
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcount_599, Variable vfirst_backup_599, BlockStmt target_9, ExprStmt target_10, RelationalOperation target_11, MulExpr target_12, RelationalOperation target_13) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vfirst_backup_599
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcount_599
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vfirst_backup_599
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(DivExpr).getValue()="1152921504606846975"
		and target_0.getParent().(IfStmt).getThen()=target_9
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_11.getGreaterOperand().(VariableAccess).getLocation())
		and target_12.getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_13.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vintervals_597, NotExpr target_8) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vintervals_597
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getCondition()=target_8)
}

predicate func_2(Variable vintervals_597, ExprStmt target_14, ArrayExpr target_15) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vintervals_597
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_15.getArrayBase().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vcd_594, Variable vintervals_597, ExprStmt target_16, ExprStmt target_17, ExprStmt target_14, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vintervals_597
		and target_3.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("logger")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcd_594
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Not enough memory."
		and target_3.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_3)
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_4(Variable vjobj_596, Variable vintervals_597, Variable vi_599, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="offset"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vintervals_597
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_599
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("json_segment_get_offset")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vjobj_596
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_5(Variable vjobj_596, Variable vintervals_597, Variable vi_599, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="length"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vintervals_597
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_599
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(FunctionCall).getTarget().hasName("json_segment_get_size")
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vjobj_596
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="18446744073709551615"
}

predicate func_6(Variable vintervals_597, Variable vfirst_backup_599, Function func, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vintervals_597
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("malloc")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vfirst_backup_599
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="16"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_7(Variable vintervals_597, BlockStmt target_9, VariableAccess target_7) {
		target_7.getTarget()=vintervals_597
		and target_7.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_9
}

predicate func_8(Variable vintervals_597, BlockStmt target_9, NotExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget()=vintervals_597
		and target_8.getParent().(IfStmt).getThen()=target_9
}

predicate func_9(Parameter vcd_594, BlockStmt target_9) {
		target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("logger")
		and target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcd_594
		and target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Not enough memory."
}

predicate func_10(Variable vcount_599, Variable vfirst_backup_599, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfirst_backup_599
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcount_599
}

predicate func_11(Variable vi_599, Variable vcount_599, RelationalOperation target_11) {
		 (target_11 instanceof GTExpr or target_11 instanceof LTExpr)
		and target_11.getLesserOperand().(VariableAccess).getTarget()=vi_599
		and target_11.getGreaterOperand().(VariableAccess).getTarget()=vcount_599
}

predicate func_12(Variable vfirst_backup_599, MulExpr target_12) {
		target_12.getLeftOperand().(VariableAccess).getTarget()=vfirst_backup_599
		and target_12.getRightOperand().(SizeofExprOperator).getValue()="16"
}

predicate func_13(Variable vi_599, Variable vfirst_backup_599, RelationalOperation target_13) {
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getLesserOperand().(VariableAccess).getTarget()=vi_599
		and target_13.getGreaterOperand().(VariableAccess).getTarget()=vfirst_backup_599
}

predicate func_14(Variable vintervals_597, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_14.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vintervals_597
}

predicate func_15(Variable vintervals_597, Variable vi_599, ArrayExpr target_15) {
		target_15.getArrayBase().(VariableAccess).getTarget()=vintervals_597
		and target_15.getArrayOffset().(VariableAccess).getTarget()=vi_599
}

predicate func_16(Parameter vcd_594, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("logger")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcd_594
		and target_16.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_16.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_16.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_16.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="No regular segment."
}

predicate func_17(Parameter vcd_594, Variable vi_599, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("logger")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcd_594
		and target_17.getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_17.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_17.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_17.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="Gap at key %d in segments object."
		and target_17.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vi_599
}

from Function func, Parameter vcd_594, Variable vjobj_596, Variable vintervals_597, Variable vi_599, Variable vcount_599, Variable vfirst_backup_599, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, VariableAccess target_7, NotExpr target_8, BlockStmt target_9, ExprStmt target_10, RelationalOperation target_11, MulExpr target_12, RelationalOperation target_13, ExprStmt target_14, ArrayExpr target_15, ExprStmt target_16, ExprStmt target_17
where
not func_0(vcount_599, vfirst_backup_599, target_9, target_10, target_11, target_12, target_13)
and not func_1(vintervals_597, target_8)
and not func_2(vintervals_597, target_14, target_15)
and not func_3(vcd_594, vintervals_597, target_16, target_17, target_14, func)
and func_4(vjobj_596, vintervals_597, vi_599, target_4)
and func_5(vjobj_596, vintervals_597, vi_599, target_5)
and func_6(vintervals_597, vfirst_backup_599, func, target_6)
and func_7(vintervals_597, target_9, target_7)
and func_8(vintervals_597, target_9, target_8)
and func_9(vcd_594, target_9)
and func_10(vcount_599, vfirst_backup_599, target_10)
and func_11(vi_599, vcount_599, target_11)
and func_12(vfirst_backup_599, target_12)
and func_13(vi_599, vfirst_backup_599, target_13)
and func_14(vintervals_597, target_14)
and func_15(vintervals_597, vi_599, target_15)
and func_16(vcd_594, target_16)
and func_17(vcd_594, vi_599, target_17)
and vcd_594.getType().hasName("crypt_device *")
and vjobj_596.getType().hasName("json_object *")
and vintervals_597.getType().hasName("interval *")
and vi_599.getType().hasName("int")
and vcount_599.getType().hasName("int")
and vfirst_backup_599.getType().hasName("int")
and vcd_594.getParentScope+() = func
and vjobj_596.getParentScope+() = func
and vintervals_597.getParentScope+() = func
and vi_599.getParentScope+() = func
and vcount_599.getParentScope+() = func
and vfirst_backup_599.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
