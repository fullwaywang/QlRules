/**
 * @name libtiff-e596d4e27c5afb7960dc360fdd3afd90ba0fb8ba-loadImage
 * @id cpp/libtiff/e596d4e27c5afb7960dc360fdd3afd90ba0fb8ba/loadImage
 * @description libtiff-e596d4e27c5afb7960dc360fdd3afd90ba0fb8ba-tools/tiffcrop.c-loadImage CVE-2016-3991
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vntiles_5740, Variable vtlsize_5746, Variable vtile_rowsize_5748, BlockStmt target_18, ExprStmt target_19, RelationalOperation target_10, ExprStmt target_20) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vntiles_5740
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtlsize_5746
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtile_rowsize_5748
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_18
		and target_19.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(FunctionCall target_21, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_1.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="File appears to be tiled, but the number of tiles, tile size, or tile rowsize is zero."
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(FunctionCall target_21, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_2.getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vntiles_5740, Variable vtlsize_5746, Variable vbuffsize_5746, FunctionCall target_21, ExprStmt target_22) {
	exists(IfStmt target_3 |
		target_3.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtlsize_5746
		and target_3.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vbuffsize_5746
		and target_3.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vntiles_5740
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Integer overflow when calculating buffer size"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(8)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_3.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_22.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getLocation()))
}

predicate func_4(Variable vntiles_5740, Variable vbuffsize_5746, Variable vtl_5747, Variable vtile_rowsize_5748, FunctionCall target_21, RelationalOperation target_10, NotExpr target_23, ExprStmt target_22) {
	exists(IfStmt target_4 |
		target_4.getCondition() instanceof RelationalOperation
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffsize_5746
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vntiles_5740
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vtl_5747
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vtile_rowsize_5748
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vntiles_5740
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vbuffsize_5746
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vtl_5747
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vtile_rowsize_5748
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Integer overflow when calculating buffer size"
		and target_4.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_10.getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_23.getOperand().(FunctionCall).getArgument(5).(VariableAccess).getLocation())
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_22.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getLocation()))
}

/*predicate func_5(Variable vntiles_5740, Variable vbuffsize_5746, Variable vtl_5747, Variable vtile_rowsize_5748, RelationalOperation target_10, ExprStmt target_24, NotExpr target_23, ExprStmt target_22) {
	exists(IfStmt target_5 |
		target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vntiles_5740
		and target_5.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vbuffsize_5746
		and target_5.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vtl_5747
		and target_5.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vtile_rowsize_5748
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Integer overflow when calculating buffer size"
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_24.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_5.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_23.getOperand().(FunctionCall).getArgument(5).(VariableAccess).getLocation())
		and target_5.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_22.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getLocation()))
}

*/
predicate func_6(Variable vnstrips_5740, Variable vstsize_5746, FunctionCall target_21) {
	exists(IfStmt target_6 |
		target_6.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnstrips_5740
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstsize_5746
		and target_6.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="File appears to be striped, but the number of stipes or stripe size is zero."
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(4)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21)
}

predicate func_7(Variable vnstrips_5740, Variable vstsize_5746, Variable vbuffsize_5746, FunctionCall target_21) {
	exists(IfStmt target_7 |
		target_7.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstsize_5746
		and target_7.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vbuffsize_5746
		and target_7.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vnstrips_5740
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_7.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Integer overflow when calculating buffer size"
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(6)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21)
}

predicate func_8(Variable vbps_5741, Variable vspp_5741, Variable vwidth_5745, Variable vlength_5745, FunctionCall target_21, ExprStmt target_25, ExprStmt target_26, ExprStmt target_27) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("uint32")
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_5745
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vwidth_5745
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vspp_5741
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbps_5741
		and target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(8)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_25.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation())
		and target_26.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation())
		and target_27.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_9(Variable vbps_5741, Variable vspp_5741, Variable vwidth_5745, Variable vlength_5745, FunctionCall target_21, RelationalOperation target_28) {
	exists(IfStmt target_9 |
		target_9.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlength_5745
		and target_9.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getLeftOperand().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getType().hasName("uint32")
		and target_9.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getLeftOperand().(DivExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="7"
		and target_9.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vwidth_5745
		and target_9.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getLeftOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vspp_5741
		and target_9.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vbps_5741
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Integer overflow detected."
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_9.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(9)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
		and target_9.getCondition().(EqualityOperation).getAnOperand().(DivExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_28.getGreaterOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_10(Variable vntiles_5740, Variable vbuffsize_5746, Variable vtl_5747, Variable vtile_rowsize_5748, BlockStmt target_18, RelationalOperation target_10) {
		 (target_10 instanceof GTExpr or target_10 instanceof LTExpr)
		and target_10.getLesserOperand().(VariableAccess).getTarget()=vbuffsize_5746
		and target_10.getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vntiles_5740
		and target_10.getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vtl_5747
		and target_10.getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vtile_rowsize_5748
		and target_10.getParent().(IfStmt).getThen()=target_18
}

predicate func_11(Variable vreadunit_5751, FunctionCall target_21, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vreadunit_5751
		and target_11.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_12(Parameter vin_5736, Variable vrowsperstrip, FunctionCall target_21, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("TIFFGetFieldDefaulted")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_5736
		and target_12.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="278"
		and target_12.getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrowsperstrip
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_13(Parameter vin_5736, Variable vstsize_5746, FunctionCall target_21, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstsize_5746
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFStripSize")
		and target_13.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_5736
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_14(Parameter vin_5736, Variable vnstrips_5740, FunctionCall target_21, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnstrips_5740
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFNumberOfStrips")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_5736
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_15(Variable vbps_5741, Variable vspp_5741, Variable vbuffsize_5746, FunctionCall target_21, IfStmt target_15) {
		target_15.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbuffsize_5746
		and target_15.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vspp_5741
		and target_15.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbps_5741
		and target_15.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_15.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getRightOperand().(Literal).getValue()="8"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffsize_5746
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_15.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="8"
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_16(Parameter vdump_5736, Variable vnstrips_5740, Variable vstsize_5746, Variable vscanlinesize_5746, Variable vrowsperstrip, FunctionCall target_21, IfStmt target_16) {
		target_16.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="infile"
		and target_16.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_5736
		and target_16.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("dump_info")
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="infile"
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_5736
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="format"
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_5736
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()=""
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Stripsize: %u, Number of Strips: %u, Rows per Strip: %u, Scanline size: %u"
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vstsize_5746
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vnstrips_5740
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vrowsperstrip
		and target_16.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vscanlinesize_5746
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_17(Variable vnstrips_5740, Variable vstsize_5746, Variable vbuffsize_5746, FunctionCall target_21, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffsize_5746
		and target_17.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vstsize_5746
		and target_17.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vnstrips_5740
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_21
}

predicate func_18(Variable vntiles_5740, Variable vbuffsize_5746, Variable vtl_5747, Variable vtile_rowsize_5748, BlockStmt target_18) {
		target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffsize_5746
		and target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vntiles_5740
		and target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vtl_5747
		and target_18.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vtile_rowsize_5748
}

predicate func_19(Variable vntiles_5740, Variable vtlsize_5746, Variable vbuffsize_5746, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffsize_5746
		and target_19.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vtlsize_5746
		and target_19.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vntiles_5740
}

predicate func_20(Parameter vin_5736, Variable vtile_rowsize_5748, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtile_rowsize_5748
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFFTileRowSize")
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_5736
}

predicate func_21(Parameter vin_5736, FunctionCall target_21) {
		target_21.getTarget().hasName("TIFFIsTiled")
		and target_21.getArgument(0).(VariableAccess).getTarget()=vin_5736
}

predicate func_22(Parameter vdump_5736, Variable vntiles_5740, Variable vtlsize_5746, Variable vtile_rowsize_5748, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("dump_info")
		and target_22.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="infile"
		and target_22.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_5736
		and target_22.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="format"
		and target_22.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdump_5736
		and target_22.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()=""
		and target_22.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Tilesize: %u, Number of Tiles: %u, Tile row size: %u"
		and target_22.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vtlsize_5746
		and target_22.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vntiles_5740
		and target_22.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vtile_rowsize_5748
}

predicate func_23(Parameter vin_5736, Variable vbps_5741, Variable vspp_5741, Variable vwidth_5745, Variable vlength_5745, Variable vtl_5747, NotExpr target_23) {
		target_23.getOperand().(FunctionCall).getTarget().hasName("readContigTilesIntoBuffer")
		and target_23.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vin_5736
		and target_23.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("unsigned char *")
		and target_23.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlength_5745
		and target_23.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vwidth_5745
		and target_23.getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("uint32")
		and target_23.getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vtl_5747
		and target_23.getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vspp_5741
		and target_23.getOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vbps_5741
}

predicate func_24(Variable vntiles_5740, Variable vbuffsize_5746, Variable vtl_5747, Variable vtile_rowsize_5748, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuffsize_5746
		and target_24.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vntiles_5740
		and target_24.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vtl_5747
		and target_24.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vtile_rowsize_5748
}

predicate func_25(Variable vbps_5741, Variable vspp_5741, ExprStmt target_25) {
		target_25.getExpr().(FunctionCall).getTarget().hasName("TIFFError")
		and target_25.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="loadImage"
		and target_25.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Invalid samples per pixel (%d) or bits per sample (%d)"
		and target_25.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vspp_5741
		and target_25.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vbps_5741
}

predicate func_26(Variable vwidth_5745, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_26.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("image_data *")
		and target_26.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vwidth_5745
}

predicate func_27(Variable vlength_5745, ExprStmt target_27) {
		target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_27.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("image_data *")
		and target_27.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlength_5745
}

predicate func_28(Variable vbps_5741, Variable vspp_5741, Variable vwidth_5745, Variable vlength_5745, Variable vbuffsize_5746, RelationalOperation target_28) {
		 (target_28 instanceof GTExpr or target_28 instanceof LTExpr)
		and target_28.getLesserOperand().(VariableAccess).getTarget()=vbuffsize_5746
		and target_28.getGreaterOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_5745
		and target_28.getGreaterOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vwidth_5745
		and target_28.getGreaterOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vspp_5741
		and target_28.getGreaterOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbps_5741
		and target_28.getGreaterOperand().(DivExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_28.getGreaterOperand().(DivExpr).getRightOperand().(Literal).getValue()="8"
}

from Function func, Parameter vin_5736, Parameter vdump_5736, Variable vnstrips_5740, Variable vntiles_5740, Variable vbps_5741, Variable vspp_5741, Variable vwidth_5745, Variable vlength_5745, Variable vstsize_5746, Variable vtlsize_5746, Variable vbuffsize_5746, Variable vscanlinesize_5746, Variable vtl_5747, Variable vtile_rowsize_5748, Variable vreadunit_5751, Variable vrowsperstrip, RelationalOperation target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, IfStmt target_15, IfStmt target_16, ExprStmt target_17, BlockStmt target_18, ExprStmt target_19, ExprStmt target_20, FunctionCall target_21, ExprStmt target_22, NotExpr target_23, ExprStmt target_24, ExprStmt target_25, ExprStmt target_26, ExprStmt target_27, RelationalOperation target_28
where
not func_0(vntiles_5740, vtlsize_5746, vtile_rowsize_5748, target_18, target_19, target_10, target_20)
and not func_1(target_21, func)
and not func_2(target_21, func)
and not func_3(vntiles_5740, vtlsize_5746, vbuffsize_5746, target_21, target_22)
and not func_4(vntiles_5740, vbuffsize_5746, vtl_5747, vtile_rowsize_5748, target_21, target_10, target_23, target_22)
and not func_6(vnstrips_5740, vstsize_5746, target_21)
and not func_7(vnstrips_5740, vstsize_5746, vbuffsize_5746, target_21)
and not func_8(vbps_5741, vspp_5741, vwidth_5745, vlength_5745, target_21, target_25, target_26, target_27)
and not func_9(vbps_5741, vspp_5741, vwidth_5745, vlength_5745, target_21, target_28)
and func_10(vntiles_5740, vbuffsize_5746, vtl_5747, vtile_rowsize_5748, target_18, target_10)
and func_11(vreadunit_5751, target_21, target_11)
and func_12(vin_5736, vrowsperstrip, target_21, target_12)
and func_13(vin_5736, vstsize_5746, target_21, target_13)
and func_14(vin_5736, vnstrips_5740, target_21, target_14)
and func_15(vbps_5741, vspp_5741, vbuffsize_5746, target_21, target_15)
and func_16(vdump_5736, vnstrips_5740, vstsize_5746, vscanlinesize_5746, vrowsperstrip, target_21, target_16)
and func_17(vnstrips_5740, vstsize_5746, vbuffsize_5746, target_21, target_17)
and func_18(vntiles_5740, vbuffsize_5746, vtl_5747, vtile_rowsize_5748, target_18)
and func_19(vntiles_5740, vtlsize_5746, vbuffsize_5746, target_19)
and func_20(vin_5736, vtile_rowsize_5748, target_20)
and func_21(vin_5736, target_21)
and func_22(vdump_5736, vntiles_5740, vtlsize_5746, vtile_rowsize_5748, target_22)
and func_23(vin_5736, vbps_5741, vspp_5741, vwidth_5745, vlength_5745, vtl_5747, target_23)
and func_24(vntiles_5740, vbuffsize_5746, vtl_5747, vtile_rowsize_5748, target_24)
and func_25(vbps_5741, vspp_5741, target_25)
and func_26(vwidth_5745, target_26)
and func_27(vlength_5745, target_27)
and func_28(vbps_5741, vspp_5741, vwidth_5745, vlength_5745, vbuffsize_5746, target_28)
and vin_5736.getType().hasName("TIFF *")
and vdump_5736.getType().hasName("dump_opts *")
and vnstrips_5740.getType().hasName("uint16")
and vntiles_5740.getType().hasName("uint16")
and vbps_5741.getType().hasName("uint16")
and vspp_5741.getType().hasName("uint16")
and vwidth_5745.getType().hasName("uint32")
and vlength_5745.getType().hasName("uint32")
and vstsize_5746.getType().hasName("uint32")
and vtlsize_5746.getType().hasName("uint32")
and vbuffsize_5746.getType().hasName("uint32")
and vscanlinesize_5746.getType().hasName("uint32")
and vtl_5747.getType().hasName("uint32")
and vtile_rowsize_5748.getType().hasName("uint32")
and vreadunit_5751.getType().hasName("int")
and vrowsperstrip.getType().hasName("uint32")
and vin_5736.getFunction() = func
and vdump_5736.getFunction() = func
and vnstrips_5740.(LocalVariable).getFunction() = func
and vntiles_5740.(LocalVariable).getFunction() = func
and vbps_5741.(LocalVariable).getFunction() = func
and vspp_5741.(LocalVariable).getFunction() = func
and vwidth_5745.(LocalVariable).getFunction() = func
and vlength_5745.(LocalVariable).getFunction() = func
and vstsize_5746.(LocalVariable).getFunction() = func
and vtlsize_5746.(LocalVariable).getFunction() = func
and vbuffsize_5746.(LocalVariable).getFunction() = func
and vscanlinesize_5746.(LocalVariable).getFunction() = func
and vtl_5747.(LocalVariable).getFunction() = func
and vtile_rowsize_5748.(LocalVariable).getFunction() = func
and vreadunit_5751.(LocalVariable).getFunction() = func
and not vrowsperstrip.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
