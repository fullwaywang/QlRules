/**
 * @name libplist-dccd9290745345896e3a4a73154576a599fd8b7b-parse_bin_node
 * @id cpp/libplist/dccd9290745345896e3a4a73154576a599fd8b7b/parse-bin-node
 * @description libplist-dccd9290745345896e3a4a73154576a599fd8b7b-src/bplist.c-parse_bin_node CVE-2017-6437
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("uint64_t")
		and target_0.getExpr().(AssignExpr).getRValue() instanceof PointerDereferenceExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vbplist_560, BlockStmt target_73) {
	exists(AddExpr target_1 |
		target_1.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_1.getAnOperand() instanceof BinaryBitwiseOperation
		and target_1.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_1.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_1.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_1.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_73)
}

predicate func_3(Parameter vbplist_560, BlockStmt target_74) {
	exists(AddExpr target_3 |
		target_3.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_3.getAnOperand() instanceof BinaryBitwiseOperation
		and target_3.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_3.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_3.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_74)
}

predicate func_5(Parameter vbplist_560, BlockStmt target_75) {
	exists(AddExpr target_5 |
		target_5.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_5.getAnOperand() instanceof BinaryBitwiseOperation
		and target_5.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_5.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_5.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_5.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_75)
}

predicate func_7(Variable vsize_563, FunctionCall target_76) {
	exists(AddExpr target_7 |
		target_7.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_7.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_76.getArgument(1).(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_9(Variable vsize_563, FunctionCall target_78) {
	exists(AddExpr target_9 |
		target_9.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_9.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_9.getAnOperand().(VariableAccess).getLocation().isBefore(target_78.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_11(Variable vsize_563, FunctionCall target_78) {
	exists(AddExpr target_11 |
		target_11.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_11.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_78.getArgument(1).(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_13(Variable vsize_563, FunctionCall target_80) {
	exists(AddExpr target_13 |
		target_13.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_13.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_13.getAnOperand().(VariableAccess).getLocation().isBefore(target_80.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_15(Function func) {
	exists(AddExpr target_15 |
		target_15.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_15.getAnOperand() instanceof MulExpr
		and target_15.getEnclosingFunction() = func)
}

predicate func_17(Function func) {
	exists(AddExpr target_17 |
		target_17.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_17.getAnOperand() instanceof MulExpr
		and target_17.getEnclosingFunction() = func)
}

predicate func_19(Variable vsize_563, FunctionCall target_81) {
	exists(AddExpr target_19 |
		target_19.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_19.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_81.getArgument(1).(VariableAccess).getLocation().isBefore(target_19.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_21(Variable vsize_563, FunctionCall target_83) {
	exists(AddExpr target_21 |
		target_21.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_21.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_21.getAnOperand().(VariableAccess).getLocation().isBefore(target_83.getArgument(2).(VariableAccess).getLocation()))
}

predicate func_23(Parameter vbplist_560, Variable vsize_563, BlockStmt target_84, FunctionCall target_83, FunctionCall target_85) {
	exists(AddExpr target_23 |
		target_23.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_23.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_23.getAnOperand() instanceof Literal
		and target_23.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_23.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_23.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_23.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_84
		and target_83.getArgument(2).(VariableAccess).getLocation().isBefore(target_23.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_23.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_85.getArgument(1).(VariableAccess).getLocation()))
}

predicate func_25(Variable vsize_563, FunctionCall target_85) {
	exists(AddExpr target_25 |
		target_25.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_25.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_85.getArgument(1).(VariableAccess).getLocation().isBefore(target_25.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_27(Variable vsize_563, FunctionCall target_87) {
	exists(AddExpr target_27 |
		target_27.getAnOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_27.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_27.getAnOperand().(VariableAccess).getLocation().isBefore(target_87.getArgument(2).(VariableAccess).getLocation()))
}

predicate func_29(Parameter vobject_560, PointerDereferenceExpr target_29) {
		target_29.getOperand().(VariableAccess).getTarget()=vobject_560
}

predicate func_30(Variable vsize_563, BinaryBitwiseOperation target_30) {
		target_30.getLeftOperand().(Literal).getValue()="1"
		and target_30.getRightOperand().(VariableAccess).getTarget()=vsize_563
}

predicate func_31(Parameter vbplist_560, BlockStmt target_73, PointerFieldAccess target_31) {
		target_31.getTarget().getName()="offset_table"
		and target_31.getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_31.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_31.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_73
}

predicate func_32(Variable vsize_563, BinaryBitwiseOperation target_32) {
		target_32.getLeftOperand().(Literal).getValue()="1"
		and target_32.getRightOperand().(VariableAccess).getTarget()=vsize_563
}

predicate func_33(Variable vsize_563, BinaryBitwiseOperation target_33) {
		target_33.getLeftOperand().(Literal).getValue()="1"
		and target_33.getRightOperand().(VariableAccess).getTarget()=vsize_563
}

predicate func_34(Variable vsize_563, MulExpr target_34) {
		target_34.getLeftOperand().(VariableAccess).getTarget()=vsize_563
		and target_34.getRightOperand().(Literal).getValue()="2"
}

predicate func_35(Variable vsize_563, MulExpr target_35) {
		target_35.getLeftOperand().(VariableAccess).getTarget()=vsize_563
		and target_35.getRightOperand().(Literal).getValue()="2"
}

predicate func_36(Variable vsize_563, VariableAccess target_36) {
		target_36.getTarget()=vsize_563
}

predicate func_37(Variable vsize_563, VariableAccess target_37) {
		target_37.getTarget()=vsize_563
}

predicate func_38(Variable vsize_563, VariableAccess target_38) {
		target_38.getTarget()=vsize_563
}

predicate func_39(Variable vsize_563, VariableAccess target_39) {
		target_39.getTarget()=vsize_563
}

predicate func_40(Variable vsize_563, VariableAccess target_40) {
		target_40.getTarget()=vsize_563
}

predicate func_41(Variable vsize_563, VariableAccess target_41) {
		target_41.getTarget()=vsize_563
}

predicate func_42(Variable vsize_563, VariableAccess target_42) {
		target_42.getTarget()=vsize_563
}

predicate func_44(Variable vsize_563, VariableAccess target_44) {
		target_44.getTarget()=vsize_563
}

predicate func_45(Variable vsize_563, VariableAccess target_45) {
		target_45.getTarget()=vsize_563
}

predicate func_46(Parameter vbplist_560, BlockStmt target_73, RelationalOperation target_88, RelationalOperation target_89, PointerArithmeticOperation target_46) {
		target_46.getAnOperand() instanceof PointerDereferenceExpr
		and target_46.getAnOperand() instanceof BinaryBitwiseOperation
		and target_46.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_46.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_46.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_73
		and target_88.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_46.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_46.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_89.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_47(Parameter vbplist_560, Parameter vobject_560, BlockStmt target_74, RelationalOperation target_90, RelationalOperation target_91, FunctionCall target_92, FunctionCall target_93, PointerArithmeticOperation target_47) {
		target_47.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_47.getAnOperand() instanceof BinaryBitwiseOperation
		and target_47.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_47.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_47.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_74
		and target_90.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_47.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_47.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_91.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_92.getArgument(0).(VariableAccess).getLocation().isBefore(target_47.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_47.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_93.getArgument(0).(VariableAccess).getLocation())
}

/*predicate func_48(Parameter vbplist_560, RelationalOperation target_90, RelationalOperation target_91, PointerFieldAccess target_48) {
		target_48.getTarget().getName()="offset_table"
		and target_48.getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_90.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_48.getQualifier().(VariableAccess).getLocation())
		and target_48.getQualifier().(VariableAccess).getLocation().isBefore(target_91.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_49(Parameter vbplist_560, Parameter vobject_560, BlockStmt target_75, RelationalOperation target_89, LogicalOrExpr target_94, FunctionCall target_93, FunctionCall target_76, PointerArithmeticOperation target_49) {
		target_49.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_49.getAnOperand() instanceof BinaryBitwiseOperation
		and target_49.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_49.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_49.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_75
		and target_89.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_49.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_49.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_94.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_93.getArgument(0).(VariableAccess).getLocation().isBefore(target_49.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_49.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_76.getArgument(0).(VariableAccess).getLocation())
}

/*predicate func_50(Parameter vbplist_560, RelationalOperation target_89, LogicalOrExpr target_94, PointerFieldAccess target_50) {
		target_50.getTarget().getName()="offset_table"
		and target_50.getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_89.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_50.getQualifier().(VariableAccess).getLocation())
		and target_50.getQualifier().(VariableAccess).getLocation().isBefore(target_94.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_51(Parameter vobject_560, Variable vsize_563, FunctionCall target_76, PointerArithmeticOperation target_51) {
		target_51.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_51.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_76.getArgument(0).(VariableAccess).getLocation().isBefore(target_51.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_52(Parameter vobject_560, PointerDereferenceExpr target_52) {
		target_52.getOperand().(VariableAccess).getTarget()=vobject_560
}

predicate func_53(Parameter vobject_560, Variable vsize_563, FunctionCall target_78, PointerArithmeticOperation target_53) {
		target_53.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_53.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_53.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_78.getArgument(0).(VariableAccess).getLocation())
}

predicate func_54(Parameter vbplist_560, RelationalOperation target_91, LogicalOrExpr target_95, PointerFieldAccess target_54) {
		target_54.getTarget().getName()="offset_table"
		and target_54.getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_91.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_54.getQualifier().(VariableAccess).getLocation())
		and target_54.getQualifier().(VariableAccess).getLocation().isBefore(target_95.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_55(Parameter vobject_560, Variable vsize_563, FunctionCall target_78, PointerArithmeticOperation target_55) {
		target_55.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_55.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_78.getArgument(0).(VariableAccess).getLocation().isBefore(target_55.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_56(Parameter vobject_560, PointerDereferenceExpr target_56) {
		target_56.getOperand().(VariableAccess).getTarget()=vobject_560
}

predicate func_57(Parameter vobject_560, Variable vsize_563, FunctionCall target_80, PointerArithmeticOperation target_57) {
		target_57.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_57.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_57.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_80.getArgument(0).(VariableAccess).getLocation())
}

predicate func_58(Parameter vbplist_560, LogicalOrExpr target_94, LogicalOrExpr target_96, PointerFieldAccess target_58) {
		target_58.getTarget().getName()="offset_table"
		and target_58.getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_94.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_58.getQualifier().(VariableAccess).getLocation())
		and target_58.getQualifier().(VariableAccess).getLocation().isBefore(target_96.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_59(Parameter vobject_560, FunctionCall target_80, PointerArithmeticOperation target_59) {
		target_59.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_59.getAnOperand() instanceof MulExpr
		and target_80.getArgument(0).(VariableAccess).getLocation().isBefore(target_59.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_60(Parameter vobject_560, PointerDereferenceExpr target_60) {
		target_60.getOperand().(VariableAccess).getTarget()=vobject_560
}

predicate func_61(Parameter vobject_560, FunctionCall target_81, PointerArithmeticOperation target_61) {
		target_61.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_61.getAnOperand() instanceof MulExpr
		and target_61.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_81.getArgument(0).(VariableAccess).getLocation())
}

predicate func_62(Parameter vbplist_560, LogicalOrExpr target_95, LogicalOrExpr target_97, PointerFieldAccess target_62) {
		target_62.getTarget().getName()="offset_table"
		and target_62.getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_95.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_62.getQualifier().(VariableAccess).getLocation())
		and target_62.getQualifier().(VariableAccess).getLocation().isBefore(target_97.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_63(Parameter vobject_560, Variable vsize_563, FunctionCall target_81, PointerArithmeticOperation target_63) {
		target_63.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_63.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_81.getArgument(0).(VariableAccess).getLocation().isBefore(target_63.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_64(Parameter vobject_560, PointerDereferenceExpr target_64) {
		target_64.getOperand().(VariableAccess).getTarget()=vobject_560
}

predicate func_65(Parameter vobject_560, Variable vsize_563, FunctionCall target_83, PointerArithmeticOperation target_65) {
		target_65.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_65.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_65.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_83.getArgument(1).(VariableAccess).getLocation())
}

predicate func_66(Parameter vbplist_560, LogicalOrExpr target_96, FunctionCall target_83, PointerFieldAccess target_66) {
		target_66.getTarget().getName()="offset_table"
		and target_66.getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_96.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_66.getQualifier().(VariableAccess).getLocation())
		and target_66.getQualifier().(VariableAccess).getLocation().isBefore(target_83.getArgument(0).(VariableAccess).getLocation())
}

predicate func_67(Parameter vbplist_560, Parameter vobject_560, Variable vsize_563, BlockStmt target_84, PointerArithmeticOperation target_67) {
		target_67.getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_67.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_67.getAnOperand() instanceof Literal
		and target_67.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_67.getParent().(GTExpr).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_67.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_84
}

/*predicate func_68(Parameter vbplist_560, FunctionCall target_83, LogicalOrExpr target_98, PointerFieldAccess target_68) {
		target_68.getTarget().getName()="offset_table"
		and target_68.getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_83.getArgument(0).(VariableAccess).getLocation().isBefore(target_68.getQualifier().(VariableAccess).getLocation())
		and target_68.getQualifier().(VariableAccess).getLocation().isBefore(target_98.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_69(Parameter vobject_560, Variable vsize_563, FunctionCall target_85, PointerArithmeticOperation target_69) {
		target_69.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_69.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_85.getArgument(0).(VariableAccess).getLocation().isBefore(target_69.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_70(Parameter vobject_560, PointerDereferenceExpr target_70) {
		target_70.getOperand().(VariableAccess).getTarget()=vobject_560
}

predicate func_71(Parameter vobject_560, Variable vsize_563, FunctionCall target_87, PointerArithmeticOperation target_71) {
		target_71.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_71.getAnOperand().(VariableAccess).getTarget()=vsize_563
		and target_71.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_87.getArgument(1).(VariableAccess).getLocation())
}

predicate func_72(Parameter vbplist_560, RelationalOperation target_99, FunctionCall target_87, PointerFieldAccess target_72) {
		target_72.getTarget().getName()="offset_table"
		and target_72.getQualifier().(VariableAccess).getTarget()=vbplist_560
		and target_99.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_72.getQualifier().(VariableAccess).getLocation())
		and target_72.getQualifier().(VariableAccess).getLocation().isBefore(target_87.getArgument(0).(VariableAccess).getLocation())
}

predicate func_73(BlockStmt target_73) {
		target_73.getStmt(0).(EmptyStmt).toString() = ";"
		and target_73.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_74(BlockStmt target_74) {
		target_74.getStmt(0).(EmptyStmt).toString() = ";"
		and target_74.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_75(BlockStmt target_75) {
		target_75.getStmt(0).(EmptyStmt).toString() = ";"
		and target_75.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_76(Parameter vobject_560, Variable vsize_563, FunctionCall target_76) {
		target_76.getTarget().hasName("parse_date_node")
		and target_76.getArgument(0).(VariableAccess).getTarget()=vobject_560
		and target_76.getArgument(1).(VariableAccess).getTarget()=vsize_563
}

predicate func_78(Parameter vobject_560, Variable vsize_563, FunctionCall target_78) {
		target_78.getTarget().hasName("parse_data_node")
		and target_78.getArgument(0).(VariableAccess).getTarget()=vobject_560
		and target_78.getArgument(1).(VariableAccess).getTarget()=vsize_563
}

predicate func_80(Parameter vobject_560, Variable vsize_563, FunctionCall target_80) {
		target_80.getTarget().hasName("parse_string_node")
		and target_80.getArgument(0).(VariableAccess).getTarget()=vobject_560
		and target_80.getArgument(1).(VariableAccess).getTarget()=vsize_563
}

predicate func_81(Parameter vobject_560, Variable vsize_563, FunctionCall target_81) {
		target_81.getTarget().hasName("parse_unicode_node")
		and target_81.getArgument(0).(VariableAccess).getTarget()=vobject_560
		and target_81.getArgument(1).(VariableAccess).getTarget()=vsize_563
}

predicate func_83(Parameter vbplist_560, Parameter vobject_560, Variable vsize_563, FunctionCall target_83) {
		target_83.getTarget().hasName("parse_array_node")
		and target_83.getArgument(0).(VariableAccess).getTarget()=vbplist_560
		and target_83.getArgument(1).(VariableAccess).getTarget()=vobject_560
		and target_83.getArgument(2).(VariableAccess).getTarget()=vsize_563
}

predicate func_84(BlockStmt target_84) {
		target_84.getStmt(0).(EmptyStmt).toString() = ";"
		and target_84.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_85(Parameter vobject_560, Variable vsize_563, FunctionCall target_85) {
		target_85.getTarget().hasName("parse_uid_node")
		and target_85.getArgument(0).(VariableAccess).getTarget()=vobject_560
		and target_85.getArgument(1).(VariableAccess).getTarget()=vsize_563
}

predicate func_87(Parameter vbplist_560, Parameter vobject_560, Variable vsize_563, FunctionCall target_87) {
		target_87.getTarget().hasName("parse_dict_node")
		and target_87.getArgument(0).(VariableAccess).getTarget()=vbplist_560
		and target_87.getArgument(1).(VariableAccess).getTarget()=vobject_560
		and target_87.getArgument(2).(VariableAccess).getTarget()=vsize_563
}

predicate func_88(Parameter vbplist_560, Parameter vobject_560, RelationalOperation target_88) {
		 (target_88 instanceof GTExpr or target_88 instanceof LTExpr)
		and target_88.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vobject_560
		and target_88.getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_88.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
}

predicate func_89(Parameter vbplist_560, RelationalOperation target_89) {
		 (target_89 instanceof GTExpr or target_89 instanceof LTExpr)
		and target_89.getGreaterOperand() instanceof PointerArithmeticOperation
		and target_89.getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_89.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
}

predicate func_90(Parameter vbplist_560, RelationalOperation target_90) {
		 (target_90 instanceof GTExpr or target_90 instanceof LTExpr)
		and target_90.getGreaterOperand() instanceof PointerArithmeticOperation
		and target_90.getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_90.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
}

predicate func_91(Parameter vbplist_560, RelationalOperation target_91) {
		 (target_91 instanceof GTExpr or target_91 instanceof LTExpr)
		and target_91.getGreaterOperand() instanceof PointerArithmeticOperation
		and target_91.getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_91.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
}

predicate func_92(Parameter vobject_560, Variable vsize_563, FunctionCall target_92) {
		target_92.getTarget().hasName("parse_uint_node")
		and target_92.getArgument(0).(VariableAccess).getTarget()=vobject_560
		and target_92.getArgument(1).(VariableAccess).getTarget()=vsize_563
}

predicate func_93(Parameter vobject_560, Variable vsize_563, FunctionCall target_93) {
		target_93.getTarget().hasName("parse_real_node")
		and target_93.getArgument(0).(VariableAccess).getTarget()=vobject_560
		and target_93.getArgument(1).(VariableAccess).getTarget()=vsize_563
}

predicate func_94(Parameter vbplist_560, LogicalOrExpr target_94) {
		target_94.getAnOperand().(RelationalOperation).getLesserOperand() instanceof PointerArithmeticOperation
		and target_94.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerDereferenceExpr
		and target_94.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_94.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_94.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
}

predicate func_95(Parameter vbplist_560, LogicalOrExpr target_95) {
		target_95.getAnOperand().(RelationalOperation).getLesserOperand() instanceof PointerArithmeticOperation
		and target_95.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerDereferenceExpr
		and target_95.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_95.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_95.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
}

predicate func_96(Parameter vbplist_560, LogicalOrExpr target_96) {
		target_96.getAnOperand().(RelationalOperation).getLesserOperand() instanceof PointerArithmeticOperation
		and target_96.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerDereferenceExpr
		and target_96.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_96.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_96.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
}

predicate func_97(Parameter vbplist_560, LogicalOrExpr target_97) {
		target_97.getAnOperand().(RelationalOperation).getLesserOperand() instanceof PointerArithmeticOperation
		and target_97.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerDereferenceExpr
		and target_97.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_97.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_97.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
}

predicate func_98(Parameter vbplist_560, LogicalOrExpr target_98) {
		target_98.getAnOperand().(RelationalOperation).getLesserOperand() instanceof PointerArithmeticOperation
		and target_98.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerDereferenceExpr
		and target_98.getAnOperand().(RelationalOperation).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_98.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_98.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
}

predicate func_99(Parameter vbplist_560, RelationalOperation target_99) {
		 (target_99 instanceof GTExpr or target_99 instanceof LTExpr)
		and target_99.getGreaterOperand() instanceof PointerArithmeticOperation
		and target_99.getLesserOperand().(PointerFieldAccess).getTarget().getName()="offset_table"
		and target_99.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbplist_560
}

from Function func, Parameter vbplist_560, Parameter vobject_560, Variable vsize_563, PointerDereferenceExpr target_29, BinaryBitwiseOperation target_30, PointerFieldAccess target_31, BinaryBitwiseOperation target_32, BinaryBitwiseOperation target_33, MulExpr target_34, MulExpr target_35, VariableAccess target_36, VariableAccess target_37, VariableAccess target_38, VariableAccess target_39, VariableAccess target_40, VariableAccess target_41, VariableAccess target_42, VariableAccess target_44, VariableAccess target_45, PointerArithmeticOperation target_46, PointerArithmeticOperation target_47, PointerArithmeticOperation target_49, PointerArithmeticOperation target_51, PointerDereferenceExpr target_52, PointerArithmeticOperation target_53, PointerFieldAccess target_54, PointerArithmeticOperation target_55, PointerDereferenceExpr target_56, PointerArithmeticOperation target_57, PointerFieldAccess target_58, PointerArithmeticOperation target_59, PointerDereferenceExpr target_60, PointerArithmeticOperation target_61, PointerFieldAccess target_62, PointerArithmeticOperation target_63, PointerDereferenceExpr target_64, PointerArithmeticOperation target_65, PointerFieldAccess target_66, PointerArithmeticOperation target_67, PointerArithmeticOperation target_69, PointerDereferenceExpr target_70, PointerArithmeticOperation target_71, PointerFieldAccess target_72, BlockStmt target_73, BlockStmt target_74, BlockStmt target_75, FunctionCall target_76, FunctionCall target_78, FunctionCall target_80, FunctionCall target_81, FunctionCall target_83, BlockStmt target_84, FunctionCall target_85, FunctionCall target_87, RelationalOperation target_88, RelationalOperation target_89, RelationalOperation target_90, RelationalOperation target_91, FunctionCall target_92, FunctionCall target_93, LogicalOrExpr target_94, LogicalOrExpr target_95, LogicalOrExpr target_96, LogicalOrExpr target_97, LogicalOrExpr target_98, RelationalOperation target_99
where
not func_0(func)
and not func_1(vbplist_560, target_73)
and not func_3(vbplist_560, target_74)
and not func_5(vbplist_560, target_75)
and not func_7(vsize_563, target_76)
and not func_9(vsize_563, target_78)
and not func_11(vsize_563, target_78)
and not func_13(vsize_563, target_80)
and not func_15(func)
and not func_17(func)
and not func_19(vsize_563, target_81)
and not func_21(vsize_563, target_83)
and not func_23(vbplist_560, vsize_563, target_84, target_83, target_85)
and not func_25(vsize_563, target_85)
and not func_27(vsize_563, target_87)
and func_29(vobject_560, target_29)
and func_30(vsize_563, target_30)
and func_31(vbplist_560, target_73, target_31)
and func_32(vsize_563, target_32)
and func_33(vsize_563, target_33)
and func_34(vsize_563, target_34)
and func_35(vsize_563, target_35)
and func_36(vsize_563, target_36)
and func_37(vsize_563, target_37)
and func_38(vsize_563, target_38)
and func_39(vsize_563, target_39)
and func_40(vsize_563, target_40)
and func_41(vsize_563, target_41)
and func_42(vsize_563, target_42)
and func_44(vsize_563, target_44)
and func_45(vsize_563, target_45)
and func_46(vbplist_560, target_73, target_88, target_89, target_46)
and func_47(vbplist_560, vobject_560, target_74, target_90, target_91, target_92, target_93, target_47)
and func_49(vbplist_560, vobject_560, target_75, target_89, target_94, target_93, target_76, target_49)
and func_51(vobject_560, vsize_563, target_76, target_51)
and func_52(vobject_560, target_52)
and func_53(vobject_560, vsize_563, target_78, target_53)
and func_54(vbplist_560, target_91, target_95, target_54)
and func_55(vobject_560, vsize_563, target_78, target_55)
and func_56(vobject_560, target_56)
and func_57(vobject_560, vsize_563, target_80, target_57)
and func_58(vbplist_560, target_94, target_96, target_58)
and func_59(vobject_560, target_80, target_59)
and func_60(vobject_560, target_60)
and func_61(vobject_560, target_81, target_61)
and func_62(vbplist_560, target_95, target_97, target_62)
and func_63(vobject_560, vsize_563, target_81, target_63)
and func_64(vobject_560, target_64)
and func_65(vobject_560, vsize_563, target_83, target_65)
and func_66(vbplist_560, target_96, target_83, target_66)
and func_67(vbplist_560, vobject_560, vsize_563, target_84, target_67)
and func_69(vobject_560, vsize_563, target_85, target_69)
and func_70(vobject_560, target_70)
and func_71(vobject_560, vsize_563, target_87, target_71)
and func_72(vbplist_560, target_99, target_87, target_72)
and func_73(target_73)
and func_74(target_74)
and func_75(target_75)
and func_76(vobject_560, vsize_563, target_76)
and func_78(vobject_560, vsize_563, target_78)
and func_80(vobject_560, vsize_563, target_80)
and func_81(vobject_560, vsize_563, target_81)
and func_83(vbplist_560, vobject_560, vsize_563, target_83)
and func_84(target_84)
and func_85(vobject_560, vsize_563, target_85)
and func_87(vbplist_560, vobject_560, vsize_563, target_87)
and func_88(vbplist_560, vobject_560, target_88)
and func_89(vbplist_560, target_89)
and func_90(vbplist_560, target_90)
and func_91(vbplist_560, target_91)
and func_92(vobject_560, vsize_563, target_92)
and func_93(vobject_560, vsize_563, target_93)
and func_94(vbplist_560, target_94)
and func_95(vbplist_560, target_95)
and func_96(vbplist_560, target_96)
and func_97(vbplist_560, target_97)
and func_98(vbplist_560, target_98)
and func_99(vbplist_560, target_99)
and vbplist_560.getType().hasName("bplist_data *")
and vobject_560.getType().hasName("const char **")
and vsize_563.getType().hasName("uint64_t")
and vbplist_560.getParentScope+() = func
and vobject_560.getParentScope+() = func
and vsize_563.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
