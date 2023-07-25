/**
 * @name ghostscript-bf72f1a3dd5392ee8291e3b1518a0c2c5dc6ba39-FloydSteinbergDitheringC
 * @id cpp/ghostscript/bf72f1a3dd5392ee8291e3b1518a0c2c5dc6ba39/FloydSteinbergDitheringC
 * @description ghostscript-bf72f1a3dd5392ee8291e3b1518a0c2c5dc6ba39-contrib/gdevbjca.c-FloydSteinbergDitheringC CVE-2020-16297
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrow_643, CommaExpr target_82) {
	exists(ArrayExpr target_0 |
		target_0.getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_0.getArrayOffset().(Literal).getValue()="0"
		and target_82.getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getArrayBase().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vrow_643) {
	exists(ArrayExpr target_1 |
		target_1.getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_1.getArrayOffset() instanceof Literal)
}

predicate func_2(Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="255"
		and target_2.getEnclosingFunction() = func)
}

predicate func_7(Parameter vrow_643) {
	exists(ArrayExpr target_7 |
		target_7.getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_7.getArrayOffset() instanceof Literal)
}

predicate func_8(Parameter vrow_643) {
	exists(ArrayExpr target_8 |
		target_8.getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_8.getArrayOffset() instanceof Literal)
}

predicate func_9(Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_9.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_9.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="255"
		and target_9.getEnclosingFunction() = func)
}

predicate func_13(Parameter vrow_643, ExprStmt target_89) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_13.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_13.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_13.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_13.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_13.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_89.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation()))
}

/*predicate func_15(Parameter vrow_643) {
	exists(ArrayExpr target_15 |
		target_15.getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_15.getArrayOffset() instanceof Literal)
}

*/
/*predicate func_16(Parameter vrow_643, ExprStmt target_89) {
	exists(ArrayExpr target_16 |
		target_16.getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_16.getArrayOffset() instanceof Literal
		and target_16.getArrayBase().(VariableAccess).getLocation().isBefore(target_89.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation()))
}

*/
predicate func_17(Function func) {
	exists(IfStmt target_17 |
		target_17.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_17.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_17.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="255"
		and target_17.getEnclosingFunction() = func)
}

predicate func_18(Parameter vdev_642, Variable verr_corrY_648, ExprStmt target_92, RelationalOperation target_93, LogicalAndExpr target_94) {
	exists(AssignExpr target_18 |
		target_18.getLValue().(VariableAccess).getTarget()=verr_corrY_648
		and target_18.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableY"
		and target_18.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_18.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_18.getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergY"
		and target_18.getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_92.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_18.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_18.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_93.getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_18.getLValue().(VariableAccess).getLocation().isBefore(target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_20(Parameter vrow_643, CommaExpr target_95) {
	exists(ArrayExpr target_20 |
		target_20.getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_20.getArrayOffset().(Literal).getValue()="0"
		and target_95.getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_20.getArrayBase().(VariableAccess).getLocation()))
}

predicate func_21(Parameter vrow_643) {
	exists(ArrayExpr target_21 |
		target_21.getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_21.getArrayOffset() instanceof Literal)
}

predicate func_22(Function func) {
	exists(IfStmt target_22 |
		target_22.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_22.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_22.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_22.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="255"
		and target_22.getEnclosingFunction() = func)
}

predicate func_23(Parameter vdev_642, Variable verr_corrC_648, ExprStmt target_98, ExprStmt target_99, ExprStmt target_100, LogicalAndExpr target_101) {
	exists(AssignExpr target_23 |
		target_23.getLValue().(VariableAccess).getTarget()=verr_corrC_648
		and target_23.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableC"
		and target_23.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_23.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_23.getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergC"
		and target_23.getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_98.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_23.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_23.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_99.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_100.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_23.getLValue().(VariableAccess).getLocation())
		and target_23.getLValue().(VariableAccess).getLocation().isBefore(target_101.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_25(Parameter vrow_643) {
	exists(AssignExpr target_25 |
		target_25.getLValue().(VariableAccess).getType().hasName("int")
		and target_25.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_25.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_25.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_25.getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal)
}

/*predicate func_26(Parameter vrow_643) {
	exists(ArrayExpr target_26 |
		target_26.getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_26.getArrayOffset() instanceof Literal)
}

*/
/*predicate func_27(Parameter vrow_643, ExprStmt target_99) {
	exists(ArrayExpr target_27 |
		target_27.getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_27.getArrayOffset() instanceof Literal)
}

*/
predicate func_28(Function func) {
	exists(IfStmt target_28 |
		target_28.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_28.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_28.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_28.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="255"
		and target_28.getEnclosingFunction() = func)
}

predicate func_29(Parameter vdev_642, Variable verr_corrM_648, ExprStmt target_106, ExprStmt target_107, ExprStmt target_108, LogicalAndExpr target_109) {
	exists(ExprStmt target_29 |
		target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_corrM_648
		and target_29.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableM"
		and target_29.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_29.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_29.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergM"
		and target_29.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_29.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_107.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_108.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_29.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_109.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_31(Parameter vrow_643, ExprStmt target_99) {
	exists(ExprStmt target_31 |
		target_31.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_31.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_31.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_31.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_31.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal)
}

/*predicate func_32(Parameter vrow_643, ExprStmt target_99) {
	exists(ArrayExpr target_32 |
		target_32.getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_32.getArrayOffset() instanceof Literal)
}

*/
/*predicate func_33(Parameter vrow_643, ExprStmt target_107) {
	exists(ArrayExpr target_33 |
		target_33.getArrayBase().(VariableAccess).getTarget()=vrow_643
		and target_33.getArrayOffset() instanceof Literal)
}

*/
predicate func_34(Function func) {
	exists(IfStmt target_34 |
		target_34.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_34.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="255"
		and target_34.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_34.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="255"
		and target_34.getEnclosingFunction() = func)
}

predicate func_35(Parameter vdev_642, Variable verr_corrY_648, ExprStmt target_99, RelationalOperation target_110, ExprStmt target_111, LogicalAndExpr target_112) {
	exists(ExprStmt target_35 |
		target_35.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_corrY_648
		and target_35.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableY"
		and target_35.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_35.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_35.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergY"
		and target_35.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_99.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_35.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_35.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_110.getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_111.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_35.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_35.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_112.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

/*predicate func_37(Parameter vdev_642, PointerFieldAccess target_37) {
		target_37.getTarget().getName()="FloydSteinbergM"
		and target_37.getQualifier().(VariableAccess).getTarget()=vdev_642
}

*/
/*predicate func_38(Parameter vdev_642, PointerFieldAccess target_38) {
		target_38.getTarget().getName()="FloydSteinbergY"
		and target_38.getQualifier().(VariableAccess).getTarget()=vdev_642
}

*/
/*predicate func_39(Parameter vdev_642, PointerFieldAccess target_39) {
		target_39.getTarget().getName()="FloydSteinbergC"
		and target_39.getQualifier().(VariableAccess).getTarget()=vdev_642
}

*/
/*predicate func_40(Parameter vdev_642, PointerFieldAccess target_40) {
		target_40.getTarget().getName()="FloydSteinbergM"
		and target_40.getQualifier().(VariableAccess).getTarget()=vdev_642
}

*/
/*predicate func_41(Parameter vdev_642, PointerFieldAccess target_41) {
		target_41.getTarget().getName()="FloydSteinbergY"
		and target_41.getQualifier().(VariableAccess).getTarget()=vdev_642
}

*/
predicate func_42(Parameter vdev_642, Variable verr_corrC_648, VariableAccess target_42) {
		target_42.getTarget()=verr_corrC_648
		and target_42.getParent().(AssignExpr).getLValue() = target_42
		and target_42.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableC"
		and target_42.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_42.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_42.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_42.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergC"
		and target_42.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
}

predicate func_43(Parameter vrow_643, VariableAccess target_43) {
		target_43.getTarget()=vrow_643
}

predicate func_45(Parameter vdev_642, Variable verr_corrM_648, VariableAccess target_45) {
		target_45.getTarget()=verr_corrM_648
		and target_45.getParent().(AssignExpr).getLValue() = target_45
		and target_45.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableM"
		and target_45.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_45.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_45.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_45.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergM"
		and target_45.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
}

predicate func_46(Parameter vrow_643, VariableAccess target_46) {
		target_46.getTarget()=vrow_643
}

predicate func_48(Parameter vrow_643, VariableAccess target_48) {
		target_48.getTarget()=vrow_643
}

predicate func_50(Parameter vdev_642, Variable verr_corrY_648, VariableAccess target_50) {
		target_50.getTarget()=verr_corrY_648
		and target_50.getParent().(AssignExpr).getLValue() = target_50
		and target_50.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableY"
		and target_50.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_50.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_50.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_50.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergY"
		and target_50.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
}

predicate func_51(Parameter vrow_643, VariableAccess target_51) {
		target_51.getTarget()=vrow_643
}

predicate func_53(Parameter vrow_643, VariableAccess target_53) {
		target_53.getTarget()=vrow_643
}

predicate func_55(Parameter vdev_642, Variable verr_corrC_648, VariableAccess target_55) {
		target_55.getTarget()=verr_corrC_648
		and target_55.getParent().(AssignExpr).getLValue() = target_55
		and target_55.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableC"
		and target_55.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_55.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_55.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_55.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergC"
		and target_55.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
}

predicate func_56(Parameter vrow_643, VariableAccess target_56) {
		target_56.getTarget()=vrow_643
}

predicate func_58(Parameter vdev_642, Variable verr_corrM_648, VariableAccess target_58) {
		target_58.getTarget()=verr_corrM_648
		and target_58.getParent().(AssignExpr).getLValue() = target_58
		and target_58.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableM"
		and target_58.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_58.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_58.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_58.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergM"
		and target_58.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
}

predicate func_59(Parameter vrow_643, VariableAccess target_59) {
		target_59.getTarget()=vrow_643
}

predicate func_61(Parameter vrow_643, VariableAccess target_61) {
		target_61.getTarget()=vrow_643
}

predicate func_63(Parameter vdev_642, Variable verr_corrY_648, VariableAccess target_63) {
		target_63.getTarget()=verr_corrY_648
		and target_63.getParent().(AssignExpr).getLValue() = target_63
		and target_63.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableY"
		and target_63.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_63.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_63.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_63.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergY"
		and target_63.getParent().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
}

predicate func_64(Parameter vrow_643, VariableAccess target_64) {
		target_64.getTarget()=vrow_643
}

predicate func_66(Parameter vrow_643, VariableAccess target_66) {
		target_66.getTarget()=vrow_643
}

predicate func_68(Parameter vrow_643, VariableAccess target_68) {
		target_68.getTarget()=vrow_643
}

predicate func_69(Parameter vrow_643, VariableAccess target_69) {
		target_69.getTarget()=vrow_643
}

predicate func_70(Parameter vrow_643, CommaExpr target_82, PointerDereferenceExpr target_70) {
		target_70.getOperand().(VariableAccess).getTarget()=vrow_643
		and target_82.getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_70.getOperand().(VariableAccess).getLocation())
}

predicate func_71(Parameter vrow_643, ExprStmt target_92, PointerDereferenceExpr target_71) {
		target_71.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrow_643
		and target_71.getOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
}

predicate func_72(Parameter vrow_643, PointerDereferenceExpr target_72) {
		target_72.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrow_643
		and target_72.getOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
}

predicate func_73(Parameter vrow_643, PointerDereferenceExpr target_73) {
		target_73.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrow_643
		and target_73.getOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
}

predicate func_74(Parameter vrow_643, ExprStmt target_92, PointerDereferenceExpr target_74) {
		target_74.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrow_643
		and target_74.getOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
}

predicate func_75(Parameter vrow_643, ExprStmt target_89, PointerDereferenceExpr target_75) {
		target_75.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrow_643
		and target_75.getOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_75.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_89.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation())
}

predicate func_76(Parameter vrow_643, CommaExpr target_95, PointerDereferenceExpr target_76) {
		target_76.getOperand().(VariableAccess).getTarget()=vrow_643
		and target_95.getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_76.getOperand().(VariableAccess).getLocation())
}

predicate func_77(Parameter vrow_643, ExprStmt target_99, PointerDereferenceExpr target_77) {
		target_77.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrow_643
		and target_77.getOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
}

predicate func_78(Parameter vrow_643, ExprStmt target_106, PointerDereferenceExpr target_78) {
		target_78.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrow_643
		and target_78.getOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
}

predicate func_79(Parameter vrow_643, ExprStmt target_107, PointerDereferenceExpr target_79) {
		target_79.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrow_643
		and target_79.getOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
}

predicate func_80(Parameter vrow_643, ExprStmt target_99, PointerDereferenceExpr target_80) {
		target_80.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrow_643
		and target_80.getOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
}

predicate func_81(Parameter vrow_643, PointerDereferenceExpr target_81) {
		target_81.getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vrow_643
		and target_81.getOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
}

predicate func_82(Parameter vrow_643, CommaExpr target_82) {
		target_82.getLeftOperand().(CommaExpr).getLeftOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_82.getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vrow_643
		and target_82.getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="4"
		and target_82.getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int *")
		and target_82.getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="3"
}

predicate func_89(Parameter vrow_643, ExprStmt target_89) {
		target_89.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vrow_643
		and target_89.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint")
		and target_89.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_89.getExpr().(AssignPointerAddExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="4"
}

predicate func_92(Parameter vdev_642, Variable verr_corrM_648, ExprStmt target_92) {
		target_92.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_corrM_648
		and target_92.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableM"
		and target_92.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_92.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_92.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_92.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergM"
		and target_92.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
}

predicate func_93(Parameter vdev_642, RelationalOperation target_93) {
		 (target_93 instanceof GTExpr or target_93 instanceof LTExpr)
		and target_93.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_93.getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_treshold"
		and target_93.getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_93.getLesserOperand().(ArrayExpr).getArrayOffset().(FunctionCall).getTarget().hasName("bjc_rand")
		and target_93.getLesserOperand().(ArrayExpr).getArrayOffset().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_642
}

predicate func_94(Variable verr_corrY_648, LogicalAndExpr target_94) {
		target_94.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=verr_corrY_648
		and target_94.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4080"
		and target_94.getAnOperand().(VariableAccess).getTarget().getType().hasName("bool")
}

predicate func_95(Parameter vrow_643, CommaExpr target_95) {
		target_95.getLeftOperand().(CommaExpr).getLeftOperand().(PostfixDecrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_95.getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerSubExpr).getLValue().(VariableAccess).getTarget()=vrow_643
		and target_95.getLeftOperand().(CommaExpr).getRightOperand().(AssignPointerSubExpr).getRValue().(Literal).getValue()="4"
		and target_95.getRightOperand().(AssignPointerSubExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int *")
		and target_95.getRightOperand().(AssignPointerSubExpr).getRValue().(Literal).getValue()="3"
}

predicate func_98(Parameter vdev_642, ExprStmt target_98) {
		target_98.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int *")
		and target_98.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergErrorsC"
		and target_98.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_98.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="3"
		and target_98.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget().getType().hasName("uint")
		and target_98.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="3"
}

predicate func_99(Parameter vdev_642, Variable verr_corrM_648, ExprStmt target_99) {
		target_99.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_corrM_648
		and target_99.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableM"
		and target_99.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_99.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_99.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_99.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergM"
		and target_99.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
}

predicate func_100(Variable verr_corrC_648, ExprStmt target_100) {
		target_100.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_100.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=verr_corrC_648
		and target_100.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int *")
		and target_100.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="3"
}

predicate func_101(Variable verr_corrC_648, LogicalAndExpr target_101) {
		target_101.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=verr_corrC_648
		and target_101.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4080"
		and target_101.getAnOperand().(VariableAccess).getTarget().getType().hasName("bool")
}

predicate func_106(Parameter vdev_642, Variable verr_corrC_648, ExprStmt target_106) {
		target_106.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_corrC_648
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableC"
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergC"
		and target_106.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
}

predicate func_107(Parameter vdev_642, Variable verr_corrY_648, ExprStmt target_107) {
		target_107.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_corrY_648
		and target_107.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_gamma_tableY"
		and target_107.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_107.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_107.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand() instanceof PointerDereferenceExpr
		and target_107.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="FloydSteinbergY"
		and target_107.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
}

predicate func_108(Variable verr_corrM_648, ExprStmt target_108) {
		target_108.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_108.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=verr_corrM_648
		and target_108.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int *")
		and target_108.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="4"
}

predicate func_109(Variable verr_corrM_648, LogicalAndExpr target_109) {
		target_109.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=verr_corrM_648
		and target_109.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4080"
		and target_109.getAnOperand().(VariableAccess).getTarget().getType().hasName("bool")
}

predicate func_110(Parameter vdev_642, RelationalOperation target_110) {
		 (target_110 instanceof GTExpr or target_110 instanceof LTExpr)
		and target_110.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_110.getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bjc_treshold"
		and target_110.getLesserOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_642
		and target_110.getLesserOperand().(ArrayExpr).getArrayOffset().(FunctionCall).getTarget().hasName("bjc_rand")
		and target_110.getLesserOperand().(ArrayExpr).getArrayOffset().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_642
}

predicate func_111(Variable verr_corrY_648, ExprStmt target_111) {
		target_111.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_111.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=verr_corrY_648
		and target_111.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int *")
		and target_111.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="5"
}

predicate func_112(Variable verr_corrY_648, LogicalAndExpr target_112) {
		target_112.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=verr_corrY_648
		and target_112.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4080"
		and target_112.getAnOperand().(VariableAccess).getTarget().getType().hasName("bool")
}

from Function func, Parameter vdev_642, Parameter vrow_643, Variable verr_corrC_648, Variable verr_corrM_648, Variable verr_corrY_648, VariableAccess target_42, VariableAccess target_43, VariableAccess target_45, VariableAccess target_46, VariableAccess target_48, VariableAccess target_50, VariableAccess target_51, VariableAccess target_53, VariableAccess target_55, VariableAccess target_56, VariableAccess target_58, VariableAccess target_59, VariableAccess target_61, VariableAccess target_63, VariableAccess target_64, VariableAccess target_66, VariableAccess target_68, VariableAccess target_69, PointerDereferenceExpr target_70, PointerDereferenceExpr target_71, PointerDereferenceExpr target_72, PointerDereferenceExpr target_73, PointerDereferenceExpr target_74, PointerDereferenceExpr target_75, PointerDereferenceExpr target_76, PointerDereferenceExpr target_77, PointerDereferenceExpr target_78, PointerDereferenceExpr target_79, PointerDereferenceExpr target_80, PointerDereferenceExpr target_81, CommaExpr target_82, ExprStmt target_89, ExprStmt target_92, RelationalOperation target_93, LogicalAndExpr target_94, CommaExpr target_95, ExprStmt target_98, ExprStmt target_99, ExprStmt target_100, LogicalAndExpr target_101, ExprStmt target_106, ExprStmt target_107, ExprStmt target_108, LogicalAndExpr target_109, RelationalOperation target_110, ExprStmt target_111, LogicalAndExpr target_112
where
not func_0(vrow_643, target_82)
and not func_1(vrow_643)
and not func_2(func)
and not func_7(vrow_643)
and not func_8(vrow_643)
and not func_9(func)
and not func_13(vrow_643, target_89)
and not func_17(func)
and not func_18(vdev_642, verr_corrY_648, target_92, target_93, target_94)
and not func_20(vrow_643, target_95)
and not func_21(vrow_643)
and not func_22(func)
and not func_23(vdev_642, verr_corrC_648, target_98, target_99, target_100, target_101)
and not func_25(vrow_643)
and not func_28(func)
and not func_29(vdev_642, verr_corrM_648, target_106, target_107, target_108, target_109)
and not func_31(vrow_643, target_99)
and not func_34(func)
and not func_35(vdev_642, verr_corrY_648, target_99, target_110, target_111, target_112)
and func_42(vdev_642, verr_corrC_648, target_42)
and func_43(vrow_643, target_43)
and func_45(vdev_642, verr_corrM_648, target_45)
and func_46(vrow_643, target_46)
and func_48(vrow_643, target_48)
and func_50(vdev_642, verr_corrY_648, target_50)
and func_51(vrow_643, target_51)
and func_53(vrow_643, target_53)
and func_55(vdev_642, verr_corrC_648, target_55)
and func_56(vrow_643, target_56)
and func_58(vdev_642, verr_corrM_648, target_58)
and func_59(vrow_643, target_59)
and func_61(vrow_643, target_61)
and func_63(vdev_642, verr_corrY_648, target_63)
and func_64(vrow_643, target_64)
and func_66(vrow_643, target_66)
and func_68(vrow_643, target_68)
and func_69(vrow_643, target_69)
and func_70(vrow_643, target_82, target_70)
and func_71(vrow_643, target_92, target_71)
and func_72(vrow_643, target_72)
and func_73(vrow_643, target_73)
and func_74(vrow_643, target_92, target_74)
and func_75(vrow_643, target_89, target_75)
and func_76(vrow_643, target_95, target_76)
and func_77(vrow_643, target_99, target_77)
and func_78(vrow_643, target_106, target_78)
and func_79(vrow_643, target_107, target_79)
and func_80(vrow_643, target_99, target_80)
and func_81(vrow_643, target_81)
and func_82(vrow_643, target_82)
and func_89(vrow_643, target_89)
and func_92(vdev_642, verr_corrM_648, target_92)
and func_93(vdev_642, target_93)
and func_94(verr_corrY_648, target_94)
and func_95(vrow_643, target_95)
and func_98(vdev_642, target_98)
and func_99(vdev_642, verr_corrM_648, target_99)
and func_100(verr_corrC_648, target_100)
and func_101(verr_corrC_648, target_101)
and func_106(vdev_642, verr_corrC_648, target_106)
and func_107(vdev_642, verr_corrY_648, target_107)
and func_108(verr_corrM_648, target_108)
and func_109(verr_corrM_648, target_109)
and func_110(vdev_642, target_110)
and func_111(verr_corrY_648, target_111)
and func_112(verr_corrY_648, target_112)
and vdev_642.getType().hasName("gx_device_bjc_printer *")
and vrow_643.getType().hasName("byte *")
and verr_corrC_648.getType().hasName("int")
and verr_corrM_648.getType().hasName("int")
and verr_corrY_648.getType().hasName("int")
and vdev_642.getFunction() = func
and vrow_643.getFunction() = func
and verr_corrC_648.(LocalVariable).getFunction() = func
and verr_corrM_648.(LocalVariable).getFunction() = func
and verr_corrY_648.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
