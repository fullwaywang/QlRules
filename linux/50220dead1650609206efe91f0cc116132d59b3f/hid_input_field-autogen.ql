/**
 * @name linux-50220dead1650609206efe91f0cc116132d59b3f-hid_input_field
 * @id cpp/linux/50220dead1650609206efe91f0cc116132d59b3f/hid_input_field
 * @description linux-50220dead1650609206efe91f0cc116132d59b3f-hid_input_field 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vfield_1271, Variable vn_1274, Variable vmin_1278, Variable vvalue_1280) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_1280
		and target_0.getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_0.getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vmin_1278
		and target_0.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="maxusage"
		and target_0.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271)
}

predicate func_1(Parameter vfield_1271, Variable vn_1274, Variable vmin_1278) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof LogicalAndExpr
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="value"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vmin_1278
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="maxusage"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271)
}

predicate func_2(Parameter vhid_1271, Parameter vfield_1271, Parameter vinterrupt_1272, Variable vn_1274, Variable vcount_1275, Variable vmin_1278, Variable vvalue_1280) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand() instanceof LogicalAndExpr
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_1280
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vmin_1278
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="maxusage"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_2.getAnOperand() instanceof ValueFieldAccess
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("search")
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="value"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_1280
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcount_1275
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("hid_process_event")
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhid_1271
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfield_1271
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="usage"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_1280
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vmin_1278
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vinterrupt_1272)
}

predicate func_3(Parameter vfield_1271, Variable vn_1274, Variable vmin_1278, Variable vmax_1279, Variable vvalue_1280) {
	exists(LogicalAndExpr target_3 |
		target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="2"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_1280
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmin_1278
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_1280
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmax_1279
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="hid"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="usage"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_1280
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vmin_1278
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getValue()="458753"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="458752"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_4(Parameter vfield_1271, Variable vn_1274, Variable vmin_1278, Variable vmax_1279) {
	exists(LogicalAndExpr target_4 |
		target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="value"
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmin_1278
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="value"
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmax_1279)
}

predicate func_5(Parameter vfield_1271, Variable vn_1274, Variable vmin_1278) {
	exists(ValueFieldAccess target_5 |
		target_5.getTarget().getName()="hid"
		and target_5.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="usage"
		and target_5.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_5.getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="value"
		and target_5.getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_5.getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_5.getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vmin_1278)
}

predicate func_6(Variable vn_1274, Variable vmin_1278, Variable vmax_1279, Variable vvalue_1280) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_1280
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmin_1278
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_1280
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmax_1279)
}

predicate func_7(Parameter vfield_1271, Variable vn_1274, Variable vmin_1278, Variable vvalue_1280) {
	exists(ValueFieldAccess target_7 |
		target_7.getTarget().getName()="hid"
		and target_7.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="usage"
		and target_7.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_7.getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vvalue_1280
		and target_7.getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_7.getQualifier().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vmin_1278)
}

predicate func_8(Parameter vfield_1271) {
	exists(PointerFieldAccess target_8 |
		target_8.getTarget().getName()="value"
		and target_8.getQualifier().(VariableAccess).getTarget()=vfield_1271)
}

predicate func_10(Parameter vfield_1271, Variable vn_1274) {
	exists(ArrayExpr target_10 |
		target_10.getArrayBase().(PointerFieldAccess).getTarget().getName()="value"
		and target_10.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_10.getArrayOffset().(VariableAccess).getTarget()=vn_1274)
}

predicate func_12(Parameter vfield_1271, Variable vn_1274, Variable vmin_1278) {
	exists(RelationalOperation target_12 |
		 (target_12 instanceof GEExpr or target_12 instanceof LEExpr)
		and target_12.getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="value"
		and target_12.getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_12.getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_12.getLesserOperand().(VariableAccess).getTarget()=vmin_1278)
}

predicate func_13(Parameter vfield_1271, Variable vn_1274, Variable vmin_1278) {
	exists(SubExpr target_13 |
		target_13.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="value"
		and target_13.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_13.getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_13.getRightOperand().(VariableAccess).getTarget()=vmin_1278
		and target_13.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="usage"
		and target_13.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271)
}

predicate func_14(Parameter vhid_1271, Parameter vfield_1271, Parameter vinterrupt_1272, Variable vn_1274, Variable vvalue_1280) {
	exists(ArrayExpr target_14 |
		target_14.getArrayBase().(VariableAccess).getTarget()=vvalue_1280
		and target_14.getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("hid_process_event")
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhid_1271
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfield_1271
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="usage"
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_14.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vinterrupt_1272)
}

predicate func_15(Parameter vfield_1271, Variable vn_1274, Variable vcount_1275, Variable vvalue_1280) {
	exists(FunctionCall target_15 |
		target_15.getTarget().hasName("search")
		and target_15.getArgument(0).(VariableAccess).getTarget()=vvalue_1280
		and target_15.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="value"
		and target_15.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfield_1271
		and target_15.getArgument(1).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vn_1274
		and target_15.getArgument(2).(VariableAccess).getTarget()=vcount_1275)
}

from Function func, Parameter vhid_1271, Parameter vfield_1271, Parameter vinterrupt_1272, Variable vn_1274, Variable vcount_1275, Variable vmin_1278, Variable vmax_1279, Variable vvalue_1280
where
not func_0(vfield_1271, vn_1274, vmin_1278, vvalue_1280)
and not func_1(vfield_1271, vn_1274, vmin_1278)
and not func_2(vhid_1271, vfield_1271, vinterrupt_1272, vn_1274, vcount_1275, vmin_1278, vvalue_1280)
and func_3(vfield_1271, vn_1274, vmin_1278, vmax_1279, vvalue_1280)
and func_4(vfield_1271, vn_1274, vmin_1278, vmax_1279)
and func_5(vfield_1271, vn_1274, vmin_1278)
and func_6(vn_1274, vmin_1278, vmax_1279, vvalue_1280)
and func_7(vfield_1271, vn_1274, vmin_1278, vvalue_1280)
and vhid_1271.getType().hasName("hid_device *")
and vfield_1271.getType().hasName("hid_field *")
and func_8(vfield_1271)
and vinterrupt_1272.getType().hasName("int")
and vn_1274.getType().hasName("unsigned int")
and func_10(vfield_1271, vn_1274)
and vcount_1275.getType().hasName("unsigned int")
and vmin_1278.getType().hasName("__s32")
and func_12(vfield_1271, vn_1274, vmin_1278)
and func_13(vfield_1271, vn_1274, vmin_1278)
and vmax_1279.getType().hasName("__s32")
and vvalue_1280.getType().hasName("__s32 *")
and func_14(vhid_1271, vfield_1271, vinterrupt_1272, vn_1274, vvalue_1280)
and func_15(vfield_1271, vn_1274, vcount_1275, vvalue_1280)
and vhid_1271.getParentScope+() = func
and vfield_1271.getParentScope+() = func
and vinterrupt_1272.getParentScope+() = func
and vn_1274.getParentScope+() = func
and vcount_1275.getParentScope+() = func
and vmin_1278.getParentScope+() = func
and vmax_1279.getParentScope+() = func
and vvalue_1280.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
