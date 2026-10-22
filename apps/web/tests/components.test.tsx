import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { FormModal } from "@/components/form";
import { Confidence, DataTable, Empty, Pagination, StateBadge } from "@/components/ui";

describe("StateBadge", () => {
  it("labels states in plain language", () => {
    render(<StateBadge value="potential_impact" />);
    expect(screen.getByText("Potential impact")).toBeInTheDocument();
  });
});

describe("Confidence", () => {
  it("keeps the dimensions separate", () => {
    render(
      <>
        <Confidence label="Match" value="high" />
        <Confidence label="Impact" value="low" />
      </>,
    );
    expect(screen.getByText("Match")).toBeInTheDocument();
    expect(screen.getByText("Impact")).toBeInTheDocument();
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("Low")).toBeInTheDocument();
  });
});

describe("DataTable", () => {
  it("renders rows, escapes untrusted text, and shows an empty state", () => {
    const rows = [{ id: "1", name: "<img src=x onerror=alert(1)>" }];
    const { container, rerender } = render(<DataTable rows={rows} columns={[{ header: "Name", cell: (r) => r.name }]} />);
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument(); // shown as text
    expect(container.querySelector("img")).toBeNull();
    rerender(<DataTable rows={[]} columns={[{ header: "Name", cell: () => null }]} empty={<Empty title="Nothing here" />} />);
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
  });
  it("supports keyboard activation of rows", () => {
    const onClick = vi.fn();
    render(<DataTable rows={[{ id: "1", name: "A" }]} columns={[{ header: "Name", cell: (r) => r.name }]} onRowClick={onClick} />);
    fireEvent.keyDown(screen.getByText("A").closest("tr")!, { key: "Enter" });
    expect(onClick).toHaveBeenCalled();
  });
});

describe("Pagination", () => {
  it("pages through results", () => {
    const onChange = vi.fn();
    render(<Pagination total={60} limit={25} offset={0} onChange={onChange} />);
    expect(screen.getByText("1–25 of 60")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Next"));
    expect(onChange).toHaveBeenCalledWith(25);
    expect(screen.getByText("Previous")).toBeDisabled();
  });
  it("hides itself when everything fits on one page", () => {
    const { container } = render(<Pagination total={10} limit={25} offset={0} onChange={() => {}} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("FormModal", () => {
  const fields = [
    { name: "name", label: "Name", required: true },
    { name: "internet_exposed", label: "Exposed", type: "checkbox" as const },
  ];

  it("submits cleaned values and surfaces server errors", async () => {
    const onSubmit = vi.fn().mockRejectedValueOnce(new Error("A vendor with this name already exists")).mockResolvedValueOnce(undefined);
    const onClose = vi.fn();
    render(<FormModal open title="Add" fields={fields} onClose={onClose} onSubmit={onSubmit} />);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Acme" } });
    fireEvent.click(screen.getByText("Save"));
    expect(await screen.findByText("A vendor with this name already exists")).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
    fireEvent.click(screen.getByText("Save"));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(onSubmit).toHaveBeenLastCalledWith({ name: "Acme", internet_exposed: false });
  });

  it("keeps what the user typed when the parent re-renders with a new initial object", () => {
    const { rerender } = render(<FormModal open title="Add" fields={fields} initial={{ criticality: "medium" }} onClose={() => {}} onSubmit={async () => {}} />);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Typed value" } });
    rerender(<FormModal open title="Add" fields={fields} initial={{ criticality: "medium" }} onClose={() => {}} onSubmit={async () => {}} />);
    expect(screen.getByLabelText("Name")).toHaveValue("Typed value");
  });

  it("renders nothing when closed", () => {
    render(<FormModal open={false} title="Add" fields={fields} onClose={() => {}} onSubmit={async () => {}} />);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
